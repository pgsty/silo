// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"fmt"
	"os"
	"path"
	"strings"
)

// Wrapper functions to os.RemoveAll, which calls reliableRemoveAll
// this is to ensure that if there is a racy parent directory
// create in between we can simply retry the operation.
func removeAll(dirPath string) (err error) {
	if dirPath == "" {
		return errInvalidArgument
	}

	if err = checkPathLength(dirPath); err != nil {
		return err
	}

	if err = reliableRemoveAll(dirPath); err != nil {
		switch {
		case isSysErrNotDir(err):
			// File path cannot be verified since one of
			// the parents is a file.
			return errFileAccessDenied
		case isSysErrPathNotFound(err):
			// This is a special case should be handled only for
			// windows, because windows API does not return "not a
			// directory" error message. Handle this specifically
			// here.
			return errFileAccessDenied
		}
	}
	return err
}

// Reliably retries os.RemoveAll if for some reason os.RemoveAll returns
// syscall.ENOTEMPTY (children has files).
func reliableRemoveAll(dirPath string) (err error) {
	i := 0
	for {
		// Removes all the directories and files.
		if err = RemoveAll(dirPath); err != nil {
			// Retry only for the first retryable error.
			if isSysErrNotEmpty(err) && i == 0 {
				i++
				continue
			}
		}
		break
	}
	return err
}

// Wrapper functions to os.MkdirAll, which calls reliableMkdirAll
// this is to ensure that if there is a racy parent directory
// delete in between we can simply retry the operation.
func mkdirAll(dirPath string, mode os.FileMode, baseDir string) (err error) {
	if dirPath == "" {
		return errInvalidArgument
	}

	if err = checkPathLength(dirPath); err != nil {
		return err
	}

	return mkdirAllErr(reliableMkdirAll(dirPath, mode, baseDir))
}

// mkdirAllErr converts an error of reliableMkdirAll into the error that
// mkdirAll returns.
func mkdirAllErr(err error) error {
	switch {
	case err == nil:
		return nil
	case isSysErrNotDir(err):
		// File path cannot be verified since one of the parents is a file.
		return errFileAccessDenied
	case isSysErrPathNotFound(err):
		// This is a special case should be handled only for
		// windows, because windows API does not return "not a
		// directory" error message. Handle this specifically here.
		return errFileAccessDenied
	default:
		return osErrToFileErr(err)
	}
}

// openFileAll is mkdirAll for the parent of filePath followed by the open
// of filePath with flags, with direct I/O when direct is set. A cleanup of a
// failed write of the same key can remove the directories in between, see
// retriesAgainstCleanup; then it creates them again. An error of the
// directory creation is the error of mkdirAll, an error of the open is the
// error of the OS call.
func openFileAll(filePath string, flags int, direct bool, baseDir string) (*os.File, error) {
	parentDir := path.Dir(filePath)
	if err := checkPathLength(parentDir); err != nil {
		return nil, err
	}
	retries := retriesAgainstCleanup(filePath, baseDir)
	for {
		// Create top level directories if they don't exist.
		// with mode 0777 mkdir honors system umask.
		if err := reliableMkdirAll(parentDir, 0o777, baseDir); err != nil {
			if retries > 0 && osIsNotExist(err) {
				retries--
				continue
			}
			return nil, mkdirAllErr(err)
		}
		var f *os.File
		var err error
		if direct {
			f, err = OpenFileDirectIO(filePath, flags, 0o666)
		} else {
			f, err = OpenFile(filePath, flags, 0o666)
		}
		if err != nil && retries > 0 && osIsNotExist(err) && flags&os.O_CREATE != 0 {
			retries--
			continue
		}
		return f, err
	}
}

// Reliably retries os.MkdirAll if for some reason os.MkdirAll returns
// syscall.ENOENT (parent does not exist).
func reliableMkdirAll(dirPath string, mode os.FileMode, baseDir string) (err error) {
	i := 0
	for {
		// Creates all the parent directories, with mode 0777 mkdir honors system umask.
		if err = osMkdirAll(dirPath, mode, baseDir); err != nil {
			// Retry only for the first retryable error.
			if osIsNotExist(err) && i == 0 {
				i++
				// Determine if os.NotExist error is because of
				// baseDir's parent being present, retry it once such
				// that the MkdirAll is retried once for the parent
				// of dirPath.
				// Because it is worth a retry to skip a different
				// baseDir which is slightly higher up the depth.
				nbaseDir := path.Dir(baseDir)
				if baseDir != "" && nbaseDir != "" && nbaseDir != SlashSeparator {
					baseDir = nbaseDir
				}
				continue
			}
		}
		break
	}
	return err
}

// Wrapper function to os.Rename, which calls reliableMkdirAll
// and reliableRenameAll. This is to ensure that if there is a
// racy parent directory delete in between we can simply retry
// the operation.
func renameAll(srcFilePath, dstFilePath, baseDir string) (err error) {
	if srcFilePath == "" || dstFilePath == "" {
		return errInvalidArgument
	}

	if err = checkPathLength(srcFilePath); err != nil {
		return err
	}
	if err = checkPathLength(dstFilePath); err != nil {
		return err
	}

	return renameAllErr(reliableRename(srcFilePath, dstFilePath, baseDir), srcFilePath, dstFilePath)
}

// renameAllErr converts an error of reliableRename into the error that
// renameAll returns.
func renameAllErr(err error, srcFilePath, dstFilePath string) error {
	switch {
	case err == nil:
		return nil
	case isSysErrNotDir(err) && !osIsNotExist(err):
		// Windows can have both isSysErrNotDir(err) and osIsNotExist(err) returning
		// true if the source file path contains an non-existent directory. In that case,
		// we want to return errFileNotFound instead, which will honored in subsequent
		// switch cases
		return errFileAccessDenied
	case isSysErrPathNotFound(err):
		// This is a special case should be handled only for
		// windows, because windows API does not return "not a
		// directory" error message. Handle this specifically here.
		return errFileAccessDenied
	case isSysErrCrossDevice(err):
		return fmt.Errorf("%w (%s)->(%s)", errCrossDeviceLink, srcFilePath, dstFilePath)
	case osIsNotExist(err):
		return errFileNotFound
	case osIsExist(err):
		// This is returned only when destination is a directory and we
		// are attempting a rename from file to directory.
		return errIsNotRegular
	default:
		return err
	}
}

// retriesAgainstCleanup returns how often a write to filePath is retried
// when a directory of its path disappears between the directory creation
// and the use of the directory: once per path level below baseDir.
//
// A failed RenameData, typically one that runs after its caller gave up,
// removes its object directory and the parents that are empty, so it can
// remove the directories that another write of the same key has just
// created. The directory creation or the write then reports "not found"
// although nothing is wrong with the write: retry, which creates the
// directories again. A cleanup removes each directory of the path at most
// once and each failed attempt needs at least one such removal, so one retry
// per path level is enough against any single cleanup.
func retriesAgainstCleanup(filePath, baseDir string) int {
	return strings.Count(strings.TrimPrefix(path.Clean(filePath), path.Clean(baseDir)), SlashSeparator)
}

// Reliably retries os.Rename if for some reason the directory creation or
// os.Rename returns syscall.ENOENT (parent does not exist) while the source
// is still in place, see retriesAgainstCleanup. The decision uses the error
// of the attempt itself, since another write can recreate the directories
// in between.
func reliableRename(srcFilePath, dstFilePath, baseDir string) (err error) {
	retries := retriesAgainstCleanup(dstFilePath, baseDir)
	for {
		if err = reliableMkdirAll(path.Dir(dstFilePath), 0o777, baseDir); err == nil {
			// After a successful parent directory create attempt a rename.
			err = Rename(srcFilePath, dstFilePath)
		}
		if err == nil || retries == 0 || !osIsNotExist(err) {
			return err
		}
		if _, serr := Lstat(path.Clean(srcFilePath)); serr != nil {
			// The source is gone: a late call, which the caller cleans up.
			return err
		}
		retries--
	}
}
