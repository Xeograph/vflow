//: ----------------------------------------------------------------------------
//: Copyright (C) 2017 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: file:    ipfix.go
//: details: IP Flow Information Export (IPFIX) entities model - https://www.iana.org/assignments/ipfix/ipfix.xhtml
//: author:  Mehrdad Arshad Rad
//: date:    02/01/2017
//:
//: Licensed under the Apache License, Version 2.0 (the "License");
//: you may not use this file except in compliance with the License.
//: You may obtain a copy of the License at
//:
//:     http://www.apache.org/licenses/LICENSE-2.0
//:
//: Unless required by applicable law or agreed to in writing, software
//: distributed under the License is distributed on an "AS IS" BASIS,
//: WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//: See the License for the specific language governing permissions and
//: limitations under the License.
//: ----------------------------------------------------------------------------

package ipfix

import (
	"io/ioutil"
	"os"
	"path"

	"gopkg.in/yaml.v2"
)

// FieldType is IPFIX Abstract Data Types RFC5102#section-3.1
type FieldType int

// ElementKey represents field specifier format ids
type ElementKey struct {
	EnterpriseNo uint32
	ElementID    uint16
	MultiTypeID  uint8
}

// InfoElementEntry represents standard name and
// type for a field - RFC5102
type InfoElementEntry struct {
	FieldID uint16
	Name    string
	Type    FieldType
}

// IANAInfoModel represents IPFIX field's name, identification and type
type IANAInfoModel map[ElementKey]InfoElementEntry

const (
	// Unknown data type
	Unknown FieldType = iota

	// Uint8 represents a non-negative integer value in the
	// range of 0 to 255.
	Uint8

	// Uint16 represents a non-negative integer value in the
	// range of 0 to 65535.
	Uint16

	// Uint32 represents a non-negative integer value in the
	// range of 0 to 4294967295.
	Uint32

	// Uint64 represents a non-negative integer value in the
	// range of 0 to 18446744073709551615.
	Uint64

	// Int8 represents an integer value in the range of -128
	// to 127.
	Int8

	// Int16 represents an integer value in the range of
	// -32768 to 32767.
	Int16

	// Int32 represents an integer value in the range of
	// -2147483648 to 2147483647.
	Int32

	// Int64 represents an integer value in the range of
	// -9223372036854775808 to 9223372036854775807.
	Int64

	// Float32 corresponds to an IEEE single-precision 32-bit
	// floating point type as defined in [IEEE.754.1985].
	Float32

	// Float64 corresponds to an IEEE double-precision 64-bit
	// floating point type as defined in [IEEE.754.1985].
	Float64

	// Boolean represents a binary value.  The only allowed
	// values are "true" and "false".
	Boolean

	// MacAddress represents a string of 6 octets.
	MacAddress

	// OctetArray represents a finite-length string of octets.
	OctetArray

	// String represents a finite-length string of valid
	String

	// DateTimeSeconds represents a time value in units of
	// seconds based on coordinated universal time (UTC).
	DateTimeSeconds

	// DateTimeMilliseconds represents a time value in units of
	// milliseconds based on coordinated universal time (UTC).
	DateTimeMilliseconds

	// DateTimeMicroseconds represents a time value in units of
	// microseconds based on coordinated universal time (UTC).
	DateTimeMicroseconds

	// DateTimeNanoseconds represents a time value in units of
	// nanoseconds based on coordinated universal time (UTC).
	DateTimeNanoseconds

	// Ipv4Address represents a value of an IPv4 address.
	Ipv4Address

	// Ipv6Address represents a value of an IPv6 address.
	Ipv6Address

	// Begin custom types
	// Either an Ipv4Address (if 4 bytes, MultiTypeID 1) or a String (otherwise, MultiTypeID 0, default)
	Ipv4OrString
)

// FieldTypes represents data types
var FieldTypes = map[string]FieldType{
	"unsigned8":            Uint8,
	"unsigned16":           Uint16,
	"unsigned32":           Uint32,
	"unsigned64":           Uint64,
	"signed8":              Int8,
	"signed16":             Int16,
	"signed32":             Int32,
	"signed64":             Int64,
	"float32":              Float32,
	"float64":              Float64,
	"boolean":              Boolean,
	"macAddress":           MacAddress,
	"octetArray":           OctetArray,
	"string":               String,
	"dateTimeSeconds":      DateTimeSeconds,
	"dateTimeMilliseconds": DateTimeMilliseconds,
	"dateTimeMicroseconds": DateTimeMicroseconds,
	"dateTimeNanoseconds":  DateTimeNanoseconds,
	"ipv4Address":          Ipv4Address,
	"ipv6Address":          Ipv6Address,
	// Begin custom types
	"ipv4OrString":         Ipv4OrString,
}

func (t FieldType) isVariableLength() bool {
	switch t {
		case
			String,
			OctetArray,
			Ipv4OrString:
			return true
	}
	return false
}

//InfoModel maps element to name and type based on the field id and enterprise id
var InfoModel IANAInfoModel;

// LoadExtElements loads ipfix elements information through ipfix.elemets file
func LoadExtElements(cfgPath string) error {
	var (
		file          = path.Join(cfgPath, "ipfix.elements")
		ipfixElements map[uint32]map[uint16][]string
	)

	if _, err := os.Stat(file); os.IsNotExist(err) {
		return err
	}

	b, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(b, &ipfixElements)
	if err != nil {
		return err
	}

	InfoModel = make(map[ElementKey]InfoElementEntry)

	for PEN, elements := range ipfixElements {
		for elementID, prop := range elements {
			if len(prop) > 1 {
				InfoModel[ElementKey{EnterpriseNo: PEN, ElementID: elementID}] =
					InfoElementEntry{FieldID: elementID, Name: prop[0], Type: FieldTypes[prop[1]]}
			}
		}
	}
	return nil
}
