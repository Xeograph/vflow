//: ----------------------------------------------------------------------------
//: Copyright (C) 2017 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: file:    marshal.go
//: details: encoding of each decoded IPFIX data sets
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
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"strconv"
)

var errUknownMarshalDataType = errors.New("unknown data type to marshal")

// JSONMarshal encodes IPFIX message
func (m *Message) JSONMarshal(b *bytes.Buffer, datasetIndex int) ([]byte, error) {
	b.WriteString("{")

	// encode agent id
	m.encodeAgent(b)

	// encode header
	m.encodeHeader(b)

	// encode data set
	if err := m.encodeDataSet(b, datasetIndex); err != nil {
		return nil, err
	}

	b.WriteString("}")

	return b.Bytes(), nil
}

func (m *Message) encodeDataSet(b *bytes.Buffer, i int) error {
	var (
		num_fields int
		num_repeats int
		counter int
		err error
	)

	data_set := m.DataSets[i]

	// This is a hack for the purple project to remove icmptype and icmpcode when ipprotocol != 1
	ip_protocol, ok := data_set[ElementKey{EnterpriseNo: 0, ElementID: 4}]
	if !ok || ip_protocol[0].Value.(uint8) != 1 {
		delete(data_set, ElementKey{EnterpriseNo: 0, ElementID: 176})
		delete(data_set, ElementKey{EnterpriseNo: 0, ElementID: 177})
	}
	// End hack

	num_fields = len(data_set)
	counter = 0
	b.WriteString("\"Data\":{")
	for eKey, fields := range data_set {
		num_repeats = len(fields)
		counter++

		b.WriteByte('"')
		b.WriteString(strconv.FormatInt(int64(eKey.EnterpriseNo), 10))
		b.WriteByte('_')
		b.WriteString(strconv.FormatInt(int64(eKey.ElementID), 10))
		if eKey.MultiTypeID != 0 {
			// Specify that this value is not the default type for its multi-type field
			b.WriteByte('_')
			b.WriteString(strconv.FormatInt(int64(eKey.MultiTypeID), 10))
		}
		b.WriteString("\":")

		if num_repeats == 1 {
			err = m.writeValue(b, fields[0].Value)
		} else {

			var filtered_values []interface{}
			for _, field := range fields {
				// don't write empty string vlues in arrays
				if s_val, ok := field.Value.(string); ok && len(s_val) == 0 {
					num_repeats -= 1
					continue
				}
				filtered_values = append(filtered_values, field.Value)
			}

			b.WriteByte('[')
			for j, val := range filtered_values {

				err = m.writeValue(b, val)
				if j < num_repeats - 1 {
					b.WriteByte(',')
				}
			}
			b.WriteByte(']')
		}
		

		if counter < num_fields {
			b.WriteByte(',')
		}
	}
	b.WriteByte('}')

	return err
}

func (m *Message) encodeHeader(b *bytes.Buffer) {
	b.WriteString("\"Header\":{\"Version\":")
	b.WriteString(strconv.FormatInt(int64(m.Header.Version), 10))
	b.WriteString(",\"Length\":")
	b.WriteString(strconv.FormatInt(int64(m.Header.Length), 10))
	b.WriteString(",\"ExportTime\":")
	b.WriteString(strconv.FormatInt(int64(m.Header.ExportTime), 10))
	b.WriteString(",\"SequenceNo\":")
	b.WriteString(strconv.FormatInt(int64(m.Header.SequenceNo), 10))
	b.WriteString(",\"DomainID\":")
	b.WriteString(strconv.FormatInt(int64(m.Header.DomainID), 10))
	b.WriteString("},")
}

func (m *Message) encodeAgent(b *bytes.Buffer) {
	b.WriteString("\"AgentID\":\"")
	b.WriteString(m.AgentID)
	b.WriteString("\",")
}

func (m *Message) writeValue(b *bytes.Buffer, val interface{}) error {
	switch val.(type) {
	case uint:
		b.WriteString(strconv.FormatUint(uint64(val.(uint)), 10))
	case uint8:
		b.WriteString(strconv.FormatUint(uint64(val.(uint8)), 10))
	case uint16:
		b.WriteString(strconv.FormatUint(uint64(val.(uint16)), 10))
	case uint32:
		b.WriteString(strconv.FormatUint(uint64(val.(uint32)), 10))
	case uint64:
		b.WriteString(strconv.FormatUint(val.(uint64), 10))
	case int:
		b.WriteString(strconv.FormatInt(int64(val.(int)), 10))
	case int8:
		b.WriteString(strconv.FormatInt(int64(val.(int8)), 10))
	case int16:
		b.WriteString(strconv.FormatInt(int64(val.(int16)), 10))
	case int32:
		b.WriteString(strconv.FormatInt(int64(val.(int32)), 10))
	case int64:
		b.WriteString(strconv.FormatInt(val.(int64), 10))
	case float32:
		b.WriteString(strconv.FormatFloat(float64(val.(float32)), 'E', -1, 32))
	case float64:
		b.WriteString(strconv.FormatFloat(val.(float64), 'E', -1, 64))
	case string:
		bytes, err := json.Marshal(val.(string))
		if err != nil {
			return err
		}
		b.Write(bytes)
	case net.IP:
		b.WriteByte('"')
		b.WriteString(val.(net.IP).String())
		b.WriteByte('"')
	case net.HardwareAddr:
		b.WriteByte('"')
		b.WriteString(val.(net.HardwareAddr).String())
		b.WriteByte('"')
	case []uint8:
		b.WriteByte('"')
		b.WriteString("0x" + hex.EncodeToString(val.([]uint8)))
		b.WriteByte('"')
	default:
		return errUknownMarshalDataType
	}

	return nil
}
