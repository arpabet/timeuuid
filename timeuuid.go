/*
 *
 * Copyright 2018-present Shvid Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package timeuuid

import (
	"crypto/rand"
	"github.com/pkg/errors"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
)

type UUID struct {

	mostSigBits   int64
	leastSigBits  int64

}

type Variant int

// Constants returned by Variant.
const (
	Invalid   = Variant(iota) // Invalid UUID
	RFC4122                   // The variant specified in RFC4122
	Reserved                  // Reserved, NCS backward compatibility.
	Microsoft                 // Reserved, Microsoft Corporation backward compatibility.
	Future                    // Reserved for future definition.
)

const (
	NUM_100NS_IN_MILLISECOND = int64(10000)
	NUM_100NS_SINCE_UUID_EPOCH = int64(0x01b21dd213814000)
)

var (

	ERROR_WRONG_LENGTH = errors.New("data must be 16 bytes in length")

	VERSION_DESC = []string {
		"WRONG UUID",
		"Time-based UUID",
		"DCE security UUID",
		"Name-based UUID",
		"Randomly generated UUID",
	}
)

func (this*UUID) UnmarshalBinary(data []byte) error {

	if len(data) != 16 {
		return ERROR_WRONG_LENGTH
	}

	this.mostSigBits = int64(binary.BigEndian.Uint64(data))
	this.leastSigBits = int64(binary.BigEndian.Uint64(data[8:]))

	return nil
}

func (this*UUID) MarshalBinary() []byte {

	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b, uint64(this.mostSigBits))
	binary.BigEndian.PutUint64(b[8:], uint64(this.leastSigBits))

	return b
}

func RandomUUID() (uuid UUID, err error) {

	var randomBytes = make([]byte, 16)
	rand.Read(randomBytes)

	randomBytes[6]  &= 0x0f;  /* clear version        */
	randomBytes[6]  |= 0x40;  /* set to version 4     */
	randomBytes[8]  &= 0x3f;  /* clear variant        */
	randomBytes[8]  |= 0x80;  /* set to IETF variant  */

	err = uuid.UnmarshalBinary(randomBytes)
	return uuid, err

}

func NameUUIDFromBytes(name []byte) (uuid UUID, err error) {

	digest := md5.Sum(name)

	digest[6]  &= 0x0f;  /* clear version        */
	digest[6]  |= 0x30;  /* set to version 3     */
	digest[8]  &= 0x3f;  /* clear variant        */
	digest[8]  |= 0x80;  /* set to IETF variant  */

	err = uuid.UnmarshalBinary(digest[:])
	return uuid, err

}

func (this*UUID) Version() int {
	// Version is bits masked by 0x000000000000F000 in MS long
	return int((this.mostSigBits >> 12) & 0x0f);
}

func (this*UUID) VersionDesc() string {
	ver := this.Version()
	if ver >= len(VERSION_DESC) || ver < 0 {
		ver = 0
	}
	return VERSION_DESC[ver]
}

func (this*UUID) Variant() Variant {

	variant := int(this.leastSigBits >> 56) & 0xFF;

	switch {
	case variant & 0xc0 == 0x80:
		return RFC4122
	case variant & 0xe0 == 0xc0:
		return Microsoft
	case variant & 0xe0 == 0xe0:
		return Future
	default:
		return Reserved
	}
}

/**
    timestamp is 60bit int64
    it is measured in 100-nanosecond units since midnight, October 15, 1582 UTC.

    only for version 1 or 2
 */

func (this*UUID) TimestampNano100() int64 {

	timeHi := this.mostSigBits & int64(0x0FFF)
	timeMid := (this.mostSigBits >> 16) & int64(0xFFFF)
	timeLow := (this.mostSigBits >> 32) & int64(0xFFFFFFFF)

	return (timeHi << 48) | (timeMid << 32) | timeLow;
}

func (this*UUID) TimestampMillis() int64 {

	return (this.TimestampNano100() - NUM_100NS_SINCE_UUID_EPOCH) / NUM_100NS_IN_MILLISECOND

}

func (this*UUID) String() string {
	dst := make([]byte, 32)
	hex.Encode(dst, this.MarshalBinary())
	return string(dst[0:8]) + "-" + string(dst[8:12]) + "-" + string(dst[12:16]) + "-" + string(dst[16:20]) + "-" + string(dst[20:32])
}




