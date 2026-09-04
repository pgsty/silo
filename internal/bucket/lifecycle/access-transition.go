// Copyright (c) 2015-2026 MinIO, Inc.
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

package lifecycle

import (
	"encoding/xml"
	"time"
)

var (
	errAccessInvalidDuration  = Errorf("Window and DemoteAfterIdle must be valid Go durations, e.g. 10m or 24h")
	errAccessInvalidWindow    = Errorf("Window must be a positive duration with AccessTransition")
	errAccessInvalidPromote   = Errorf("PromoteAfterAccesses must be a positive integer with AccessTransition")
	errAccessInvalidDemote    = Errorf("DemoteAfterAccesses must be smaller than PromoteAfterAccesses and 0 or greater")
	errAccessInvalidIdle      = Errorf("DemoteAfterIdle must be a positive duration no shorter than Window")
	errAccessInvalidQuotaSize = Errorf("AccessTierQuota must be a valid size, e.g. 500GiB")
)

// Duration is a time.Duration that marshals to and from an XML element
// holding a Go duration string, e.g. <Window>10m</Window>.
type Duration time.Duration

// UnmarshalXML parses a duration string such as "10m" or "24h".
func (d *Duration) UnmarshalXML(dec *xml.Decoder, start xml.StartElement) error {
	var s string
	if err := dec.DecodeElement(&s, &start); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return errAccessInvalidDuration
	}
	*d = Duration(dur)
	return nil
}

// MarshalXML encodes a non-zero duration, and nothing otherwise.
func (d Duration) MarshalXML(enc *xml.Encoder, start xml.StartElement) error {
	if d == 0 {
		return nil
	}
	return enc.EncodeElement(time.Duration(d).String(), start)
}

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration {
	return time.Duration(d)
}

// AccessTransition is a Silo extension to the S3 lifecycle rule. It relocates
// an object between server pools based on how often it is read, rather than on
// its age: an object read at least PromoteAfterAccesses times within Window
// moves to the fastest configured pool, and moves back once it has been idle
// for DemoteAfterIdle and its windowed hit count has fallen to
// DemoteAfterAccesses or below.
//
// The gap between the two thresholds, together with DemoteAfterIdle and the
// server-side access_min_residency, is what keeps an object from oscillating
// between pools.
type AccessTransition struct {
	XMLName              xml.Name `xml:"AccessTransition"`
	Window               Duration `xml:"Window,omitempty"`
	PromoteAfterAccesses int      `xml:"PromoteAfterAccesses,omitempty"`
	DemoteAfterAccesses  int      `xml:"DemoteAfterAccesses,omitempty"`
	DemoteAfterIdle      Duration `xml:"DemoteAfterIdle,omitempty"`

	set bool
}

// IsNull returns true if no usable access transition is configured.
func (a AccessTransition) IsNull() bool {
	return !a.set || a.PromoteAfterAccesses <= 0
}

// MarshalXML encodes an AccessTransition element, and nothing if unset.
func (a AccessTransition) MarshalXML(enc *xml.Encoder, start xml.StartElement) error {
	if !a.set {
		return nil
	}
	type accessTransitionWrapper AccessTransition
	return enc.EncodeElement(accessTransitionWrapper(a), start)
}

// UnmarshalXML decodes an AccessTransition element.
func (a *AccessTransition) UnmarshalXML(dec *xml.Decoder, start xml.StartElement) error {
	type accessTransitionWrapper AccessTransition
	var atw accessTransitionWrapper
	if err := dec.DecodeElement(&atw, &start); err != nil {
		return err
	}
	*a = AccessTransition(atw)
	a.set = true
	return nil
}

// Validate checks the AccessTransition element.
func (a AccessTransition) Validate() error {
	if !a.set {
		return nil
	}
	if a.Window <= 0 {
		return errAccessInvalidWindow
	}
	if a.PromoteAfterAccesses <= 0 {
		return errAccessInvalidPromote
	}
	if a.DemoteAfterAccesses < 0 || a.DemoteAfterAccesses >= a.PromoteAfterAccesses {
		return errAccessInvalidDemote
	}
	if a.DemoteAfterIdle <= 0 || a.DemoteAfterIdle < a.Window {
		return errAccessInvalidIdle
	}
	return nil
}
