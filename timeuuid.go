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
	"crypto/sha1"
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

	ErrorWrongLen = errors.New("data must be 16 bytes in length")

)

type Version int

// Constants returned by Version.
const (
	BadVersion   = Version(iota)
	TimebasedUUID
	DCESecurityUUID
	MD5NamebasedUUID
	RandomlyGeneratedUUID
	SHA1NamebasedUUID
	UnknownVersion
)

/**
     Convert serialized 16 bytes to UUID
 */

func (this*UUID) UnmarshalBinary(data []byte) error {

	if len(data) < 16 {
		return ErrorWrongLen
	}

	this.mostSigBits = int64(binary.BigEndian.Uint64(data))
	this.leastSigBits = int64(binary.BigEndian.Uint64(data[8:]))

	return nil
}

/**
     Convert sortable representation of serialized 16 bytes to UUID

     Sortable representation flips timestamp blocks to make TimeUUID sortable as byte array
 */

func (this*UUID) UnmarshalSortableBinary(data []byte) error {

	if len(data) < 16 {
		return ErrorWrongLen
	}

	timeHighAndVersion := uint64(binary.BigEndian.Uint16(data))
	timeMid := uint64(binary.BigEndian.Uint16(data[2:]))
	timeLow := uint64(binary.BigEndian.Uint32(data[4:]))

	msb := (timeLow << 32) | (timeMid << 16) | timeHighAndVersion;

	this.mostSigBits = int64(msb)
	this.leastSigBits = int64(binary.BigEndian.Uint64(data[8:]))

	return nil
}

/**
     Stores UUID in to 16 bytes
 */

func (this*UUID) MarshalBinary() []byte {

	dst := make([]byte, 16)
	this.MarshalBinaryTo(dst)
	return dst
}

/**
     Stores UUID in to slice
 */

func (this*UUID) MarshalBinaryTo(dst []byte) error {

	if len(dst) < 16 {
		return ErrorWrongLen
	}

	binary.BigEndian.PutUint64(dst, uint64(this.mostSigBits))
	binary.BigEndian.PutUint64(dst[8:], uint64(this.leastSigBits))

	return nil
}

/**
     Stores UUID in to 16 bytes by flipping timestamp parts to make byte array sortable
 */

func (this*UUID) MarshalSortableBinary() []byte {
	dst := make([]byte, 16)
	this.MarshalSortableBinaryTo(dst)
	return dst
}

/**
     Stores UUID in to slice by flipping timestamp parts to make byte array sortable
 */

func (this*UUID) MarshalSortableBinaryTo(dst []byte) error {

	if len(dst) < 16 {
		return ErrorWrongLen
	}

	timeHighAndVersion := uint16(this.mostSigBits)
	timeMid := uint16(this.mostSigBits >> 16)
	timeLow := uint32(this.mostSigBits >> 32)

	binary.BigEndian.PutUint16(dst, timeHighAndVersion)
	binary.BigEndian.PutUint16(dst[2:], timeMid)
	binary.BigEndian.PutUint32(dst[4:], timeLow)
	binary.BigEndian.PutUint64(dst[8:], uint64(this.leastSigBits))

	return nil
}

/**
     Flips timestamp parts to make byte array sortable
 */

func ConvertBinaryToSortableBinary(uuid []byte) ([]byte, error) {

	if len(uuid) < 16 {
		return nil, ErrorWrongLen
	}

	srt := make([]byte, 16)

	copy(srt[0:2], uuid[6:8])
	copy(srt[2:4], uuid[4:6])
	copy(srt[4:8], uuid[0:4])
	copy(srt[8:16], uuid[8:16])

	return srt, nil

}

/**
     Restores original uuid byte array from sortable one
 */

func ConvertSortableBinaryToBinary(srt []byte) ([]byte, error) {

	if len(srt) < 16 {
		return nil, ErrorWrongLen
	}

	uuid := make([]byte, 16)

	copy(uuid[0:4], srt[4:8])
	copy(uuid[4:6], srt[2:4])
	copy(uuid[6:8], srt[0:2])
	copy(uuid[8:16], srt[8:16])

	return uuid, nil
}

/**
    Generates random UUID by using pseudo-random cryptographic generator
 */

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

/**
	Creates UUID based on MD5 digest of incoming byte array
    Used for authentication purposes
 */

func MD5NameUUIDFromBytes(name []byte) (uuid UUID, err error) {

	digest := md5.Sum(name)

	digest[6]  &= 0x0f;  /* clear version        */
	digest[6]  |= 0x30;  /* set to version 3     */
	digest[8]  &= 0x3f;  /* clear variant        */
	digest[8]  |= 0x80;  /* set to IETF variant  */

	err = uuid.UnmarshalBinary(digest[:])
	return uuid, err

}

/**
	Creates UUID based on SHA1 digest of incoming byte array
    Used for authentication purposes
 */

func SHA1NameUUIDFromBytes(name []byte) (uuid UUID, err error) {

	digest := sha1.Sum(name)

	digest[6] &= 0x0f;  /* clear version        */
	digest[6] |= 0x50;  /* set to version 5     */
	digest[8] &= 0x3f;  /* clear variant        */
	digest[8] |= 0x80;  /* set to IETF variant  */

	err = uuid.UnmarshalBinary(digest[:])
	return uuid, err

}

/**
    Gets version of the UUID
 */

func (this*UUID) Version() Version {

	// Version is bits masked by 0x000000000000F000 in MS long
	version := int((this.mostSigBits >> 12) & 0x0f);

	if version >= int(UnknownVersion) {
		return UnknownVersion
	}

	return Version(version)
}

/**
	Gets variant of the UUID
 */

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
    Gets timestamp as 60bit int64 from Time-based UUID

    It is measured in 100-nanosecond units since midnight, October 15, 1582 UTC.

    valid only for version 1 or 2
 */

func (this*UUID) Time100Nanos() int64 {

	timeHigh := this.mostSigBits & int64(0x0FFF)
	timeMid := (this.mostSigBits >> 16) & int64(0xFFFF)
	timeLow := (this.mostSigBits >> 32) & int64(0xFFFFFFFF)

	return (timeHigh << 48) | (timeMid << 32) | timeLow;
}

/**
	Gets timestamp in milliseconds from Time-based UUID

	It is measured in millisecond units in unix time since 1 Jan 1970
 */

func (this*UUID) TimestampMillis() int64 {

	return (this.Time100Nanos() - NUM_100NS_SINCE_UUID_EPOCH) / NUM_100NS_IN_MILLISECOND

}

/**
    Gets 14 bit clock sequence value from Time-based UUID
 */

func (this*UUID) ClockSequence() int {

	variantAndSequence := int(this.leastSigBits >> 48);

	return variantAndSequence & 0x3FFF;
}

/**
    Gets node associated with Time-based UUID

    48 bit node is intended to hold the IEEE 802 address of the machine that generated this UUID to guarantee spatial uniqueness.

 */

func (this*UUID) Node() int64 {

	return this.leastSigBits & int64(0x0000FFFFFFFFFFFF);

}

/**
	Converts UUID in to string

	<time_low> "-" <time_mid> "-" <time_high_and_version> "-" <variant_and_sequence> "-" <node>

	time_low               = 4*<hexOctet>
    time_mid               = 2*<hexOctet>
    time_high_and_version  = 2*<hexOctet>
    variant_and_sequence   = 2*<hexOctet>
    node                   = 6*<hexOctet>

 */

func (this*UUID) String() string {
	dst := make([]byte, 32)
	hex.Encode(dst, this.MarshalBinary())
	return string(dst[0:8]) + "-" + string(dst[8:12]) + "-" + string(dst[12:16]) + "-" + string(dst[16:20]) + "-" + string(dst[20:32])
}






