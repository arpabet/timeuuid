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
	"fmt"
	"bytes"
	"time"
)

type UUID struct {

	mostSigBits   uint64
	leastSigBits  uint64

}

var ZeroUUID = UUID{0, 0}

type Variant int

// Constants returned by Variant.
const (
	NCSReserved   = Variant(iota)
	IETF                      // The IETF variant specified in RFC4122
	MicrosoftReserved         // Reserved, Microsoft Corporation backward compatibility.
	FutureReserved            // Reserved for future definition.
	UnknownVariant
)

const (

	IETFVariant = uint64(0x80) << 56

	One100NanosInSecond       = int64(time.Second) / 100
	One100NanosInMillis       = int64(time.Millisecond) / 100
	Num100NanosSinceUUIDEpoch = int64(0x01b21dd213814000)

	VersionMask = uint64(0x000000000000F000)
	TimebasedVersion = uint64(0x0000000000001000)

	MinNode = int64(0)
	MaxNode = int64(0x0000FFFFFFFFFFFF)
	NodeClearMask = uint64(0xFFFF000000000000)

	MinClockSequence = int(0)
	MaxClockSequence = int(0x3FFF)
	ClockSequenceClearMask = uint64(0xC000FFFFFFFFFFFF)

	FlipSignedBits = uint64(0x0080808080808080)

	CounterMask = uint64(0x3FFFFFFFFFFFFFFF)

	MinCounterLeastBits = uint64(0x0080808080808080)
	MaxCounterLeastBits = uint64(0x7f7f7f7f7f7f7f7f)

)

var (
	ErrorWrongLen = errors.New("wrong len")
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

func (this UUID) Equal(other UUID) bool {
	return this.mostSigBits == other.mostSigBits && this.leastSigBits == other.leastSigBits
}

/**
	Creates new UUID for the specific version
 */

func NewUUID(version Version) (uuid UUID) {

	uuid.mostSigBits = uint64(version) << 12
	uuid.leastSigBits = IETFVariant

	return uuid
}

/**
	Gets most significant bits as long
 */

func (this UUID) MostSignificantBits() int64 {
	return int64(this.mostSigBits)
}

/**
	Sets most significant bits from long
 */

func (this*UUID) SetMostSignificantBits(mostSigBits int64) {
	this.mostSigBits = uint64(mostSigBits)
}

/**
	Gets least significant bits as long
 */

func (this UUID) LeastSignificantBits() int64 {
	return int64(this.leastSigBits);
}

/**
	Sets least significant bits from long
 */

func (this*UUID) SetLeastSignificantBits(leastSigBits int64) {
	this.leastSigBits = uint64(leastSigBits)
}

/**
     Convert serialized 16 bytes to UUID

     UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
 */

func (this*UUID) UnmarshalBinary(data []byte) error {

	if len(data) < 16 {
		return ErrorWrongLen
	}

	this.mostSigBits = binary.BigEndian.Uint64(data)
	this.leastSigBits = binary.BigEndian.Uint64(data[8:])

	return nil
}

/**
     Convert sortable representation of serialized 16 bytes to UUID

     Sortable representation flips timestamp blocks to make TimeUUID sortable as byte array and converts signed bytes to unsigned
 */

func (this*UUID) UnmarshalSortableBinary(data []byte) error {

	if len(data) < 16 {
		return ErrorWrongLen
	}

	timeHighAndVersion := uint64(binary.BigEndian.Uint16(data))
	timeMid := uint64(binary.BigEndian.Uint16(data[2:]))
	timeLow := uint64(binary.BigEndian.Uint32(data[4:]))

	this.mostSigBits = (timeLow << 32) | (timeMid << 16) | timeHighAndVersion
	this.leastSigBits = binary.BigEndian.Uint64(data[8:]) ^ FlipSignedBits

	return nil
}

/**
     Stores UUID in to 16 bytes

     MarshalBinary implements the encoding.BinaryMarshaler interface.
 */

func (this UUID) MarshalBinary() (dst []byte, err error) {

	dst = make([]byte, 16)
	err = this.MarshalBinaryTo(dst)
	return dst, err

}

/**
     Stores UUID in to slice
 */

func (this UUID) MarshalBinaryTo(dst []byte) error {

	if len(dst) < 16 {
		return ErrorWrongLen
	}

	binary.BigEndian.PutUint64(dst, this.mostSigBits)
	binary.BigEndian.PutUint64(dst[8:], this.leastSigBits)

	return nil
}

/**
     Stores UUID in to 16 bytes by flipping timestamp parts to make byte array sortable
 */

func (this UUID) MarshalSortableBinary() []byte {
	dst := make([]byte, 16)
	this.MarshalSortableBinaryTo(dst)
	return dst
}

/**
     Stores UUID in to slice by flipping timestamp parts to make byte array sortable and converts signed bytes to unsigned
 */

func (this UUID) MarshalSortableBinaryTo(dst []byte) error {

	if len(dst) < 16 {
		return ErrorWrongLen
	}

	timeHighAndVersion := uint16(this.mostSigBits)
	timeMid := uint16(this.mostSigBits >> 16)
	timeLow := uint32(this.mostSigBits >> 32)

	binary.BigEndian.PutUint16(dst, timeHighAndVersion)
	binary.BigEndian.PutUint16(dst[2:], timeMid)
	binary.BigEndian.PutUint32(dst[4:], timeLow)
	binary.BigEndian.PutUint64(dst[8:], this.leastSigBits ^FlipSignedBits)

	return nil
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
	Creates UUID based on digest of incoming byte array
    Used for authentication purposes
 */

func NameUUIDFromBytes(name []byte, version Version) (uuid UUID, err error) {
	err = uuid.SetName(name, version)
	return uuid, err
}

/**
	Sets name digest of incoming byte array
    Used for authentication purposes
 */

func (this*UUID) SetName(name []byte, version Version) error {

	switch(version) {

	case MD5NamebasedUUID:

		digest := md5.Sum(name)

		digest[6]  &= 0x0f;  /* clear version        */
		digest[6]  |= 0x30;  /* set to version 3     */
		digest[8]  &= 0x3f;  /* clear variant        */
		digest[8]  |= 0x80;  /* set to IETF variant  */

		return this.UnmarshalBinary(digest[:])

	case SHA1NamebasedUUID:

		digest := sha1.Sum(name)

		digest[6] &= 0x0f;  /* clear version        */
		digest[6] |= 0x50;  /* set to version 5     */
		digest[8] &= 0x3f;  /* clear variant        */
		digest[8] |= 0x80;  /* set to IETF variant  */

		return this.UnmarshalBinary(digest[:])

	default:
		return errors.Errorf("unknown version: %q", version)
	}

}

/**
    Gets version of the UUID
 */

func (this UUID) Version() Version {

	version := int((this.mostSigBits & VersionMask) >> 12)

	if version >= int(UnknownVersion) {
		return UnknownVersion
	}

	return Version(version)
}

/**
	Gets variant of the UUID
 */

func (this UUID) Variant() Variant {

	variant := int((this.leastSigBits >> 56) & 0xFF);

	// This field is composed of a varying number of bits.
	// 0    x    x   x   Reserved for NCS backward compatibility
	// 1    0    x   x   The IETF aka Leach-Salz variant (used by this class)
	// 1    1    0   x   Reserved, Microsoft backward compatibility
	// 1    1    1   x   Reserved for future definition.

	switch {
	case variant & 0x80 == 0:
		return NCSReserved
	case variant & 0xC0 == 0x80:
		return IETF
	case variant & 0xE0 == 0xC0:
		return MicrosoftReserved
	case variant & 0xE0 == 0xE0:
		return FutureReserved
	default:
		return UnknownVariant
	}
}

/**
    Gets timestamp as 60bit int64 from Time-based UUID

    It is measured in 100-nanosecond units since midnight, October 15, 1582 UTC.

    valid only for version 1 or 2
 */

func (this UUID) Time100Nanos() int64 {
	return int64(this.Time100NanosUnsigned())
}

/**
    Gets timestamp as 60bit int64 from Time-based UUID

    It is measured in 100-nanosecond units since midnight, October 15, 1582 UTC.

    valid only for version 1 or 2
 */

func (this UUID) Time100NanosUnsigned() uint64 {

	timeHigh := this.mostSigBits & 0x0FFF
	timeMid := (this.mostSigBits >> 16) & 0xFFFF
	timeLow := (this.mostSigBits >> 32) & 0xFFFFFFFF

	return (timeHigh << 48) | (timeMid << 32) | timeLow
}

/**
	Sets time in 100 nanoseconds since midnight, October 15, 1582 UTC.
 */

func (this*UUID) SetTime100Nanos(time100Nanos int64) {
	this.SetTime100NanosUnsigned(uint64(time100Nanos))
}

/**
	Sets time in 100 nanoseconds since midnight, October 15, 1582 UTC.
 */

func (this*UUID) SetTime100NanosUnsigned(time100Nanos uint64) {

	bits := TimebasedVersion

	// timeLow
	bits |= (time100Nanos & 0xFFFFFFFF) << 32

	// timeMid
	bits |= (time100Nanos & 0xFFFF00000000) >> 16

	// timeHigh
	bits |= (time100Nanos & 0xFFF000000000000) >> 48

	this.mostSigBits = bits

}

/**
	Gets timestamp in milliseconds from Time-based UUID

	It is measured in millisecond units in unix time since 1 Jan 1970
 */

func (this UUID) UnixTimeMillis() int64 {

	return (this.Time100Nanos() - Num100NanosSinceUUIDEpoch) / One100NanosInMillis

}

/**
	Sets timestamp in milliseconds to Time-based UUID

    It is measured in millisecond units in unix time since 1 Jan 1970
 */

func (this*UUID) SetUnixTimeMillis(unixTimeMillis int64) {

	time100Nanos := (unixTimeMillis * One100NanosInMillis) + Num100NanosSinceUUIDEpoch

	this.SetTime100Nanos(time100Nanos)
}

/**
	Gets timestamp in 100 nanoseconds from Time-based UUID

	It is measured in millisecond units in unix time since 1 Jan 1970
 */

func (this UUID) UnixTime100Nanos() int64 {

	return this.Time100Nanos() - Num100NanosSinceUUIDEpoch

}

/**
	Sets timestamp in 100 nanoseconds to Time-based UUID

    It is measured in millisecond units in unix time since 1 Jan 1970
 */

func (this*UUID) SetUnixTime100Nanos(unixTime100Nanos int64) {

	this.SetTime100Nanos(unixTime100Nanos + Num100NanosSinceUUIDEpoch)
}


/**
	Gets Time from Time-based UUID
 */

func (this UUID) Time() time.Time {
	unixTime100Nanos := this.UnixTime100Nanos()
	return time.Unix(unixTime100Nanos /One100NanosInSecond, (unixTime100Nanos %One100NanosInSecond) * 100)
}

/**
	Sets Time to Time-based UUID
 */

func (this*UUID) SetTime(t time.Time) {
	sec := t.Unix()
	nsec := int64(t.Nanosecond())
	one100Nanos := (nsec / 100) % One100NanosInSecond
	this.SetUnixTime100Nanos(sec *One100NanosInSecond + one100Nanos)
}


/**
    Gets raw 14 bit clock sequence value from Time-based UUID

    unsigned in range [0, 0x3FFF]

    Does not convert signed to unsigned
 */

func (this UUID) ClockSequence() int {

	variantAndSequence := this.leastSigBits >> 48;

	return int(variantAndSequence) & MaxClockSequence;
}

/**
	Sets raw 14 bit clock sequence value to Time-based UUID

    unsigned in range [0, 0x3FFF]

    Does not convert signed to unsigned
 */

func (this* UUID) SetClockSequence(clockSequence int) {

	sanitizedSequence := uint64(clockSequence & MaxClockSequence)

	this.leastSigBits = (this.leastSigBits & ClockSequenceClearMask) | (sanitizedSequence << 48)
}


/**
    Gets raw node value associated with Time-based UUID

    48 bit node is intended to hold the IEEE 802 address of the machine that generated this UUID to guarantee spatial uniqueness.

    unsigned in range [0, 0xFFFFFFFFFFFF]

    Does not convert signed to unsigned
 */

func (this UUID) Node() int64 {
	return int64(this.leastSigBits) & MaxNode;
}

/**
	Stores raw 48 bit value to the node

    unsigned in range [0, 0xFFFFFFFFFFFF]

    Does not convert signed to unsigned
 */

func (this*UUID) SetNode(node int64) {
	sanitizedNode := uint64(node & MaxNode)
	this.leastSigBits = (this.leastSigBits & NodeClearMask) | sanitizedNode
}

/**
	Gets counter in range [0 to 3fffffffffffffff]

    Counter is the composition of ClockSequenceAndNode

    Converts from signed values automatically
 */

func (this UUID) Counter() int64 {
	return int64(this.CounterUnsigned())
}

/**
	Gets counter in range [0 to 3fffffffffffffff]

    Counter is the composition of ClockSequenceAndNode

    Converts from signed values automatically
 */

func (this UUID) CounterUnsigned() uint64 {
	return (this.leastSigBits ^ FlipSignedBits) & CounterMask
}

/**
	Sets counter in range [0 to 3fffffffffffffff]

    Counter is the composition of ClockSequenceAndNode

    Converts to signed values automatically

    return sanitized value stored in UUID
 */

func (this* UUID) SetCounter(counter int64) int64 {
	return int64(this.SetCounterUnsigned(uint64(counter)))
}

/**
	Sets counter in range [0 to 3fffffffffffffff]

    Counter is the composition of ClockSequenceAndNode

    Converts to signed values automatically

    return sanitized value stored in UUID
 */

func (this* UUID) SetCounterUnsigned(counter uint64) uint64 {
	sanitizedCounter := counter & CounterMask
	this.leastSigBits = (sanitizedCounter | IETFVariant) ^ FlipSignedBits
	return sanitizedCounter
}

/**
    Sets min counter

    Guarantees that in sortable binary block will be first after sorting
 */

func (this* UUID) SetMinCounter() {
	this.leastSigBits = MinCounterLeastBits | IETFVariant
}

/**
    Sets max counter

    Guarantees that in sortable binary block will be last after sorting
 */

func (this* UUID) SetMaxCounter() {
	this.leastSigBits = MaxCounterLeastBits | IETFVariant
}

/**
	Parses string representation of UUID
 */

func Parse(s string) (UUID, error) {
	return ParseBytes([]byte(s))
}

/**
   Parses bytes are a string representation of UUID
 */

func ParseBytes(src []byte) (UUID, error) {

	for {

		switch len(src) {

		// xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
		case 36:
			if src[8] != '-' || src[13] != '-' || src[18] != '-' || src[23] != '-' {
				return ZeroUUID, fmt.Errorf("invalid UUID format: %q", src)
			}
			var trunc [32]byte
			copy(trunc[:8], src[:8])
			copy(trunc[8:12], src[9:13])
			copy(trunc[12:16], src[14:18])
			copy(trunc[16:20], src[19:23])
			copy(trunc[20:], src[24:36])
			src = trunc[:]

			// urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
		case 36 + 9:
			if !bytes.Equal(bytes.ToLower(src[:9]), []byte("urn:uuid:")) {
				return ZeroUUID, fmt.Errorf("invalid urn prefix in %q", src)
			}
			src = src[9:]

			// {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} or "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" or similar
		case 36 + 2:
			src = src[1:37]

			// xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
		case 32:
			var data [16]byte
			hex.Decode(data[:], src)
			var uuid UUID
			err := uuid.UnmarshalBinary(data[:])
			return uuid, err

		default:
			fmt.Printf("finish %s", src)
			return ZeroUUID, fmt.Errorf("invalid UUID length: %q", src)
		}

	}
}

/**
	UnmarshalText implements the encoding.TextUnmarshaler interface.
 */

func (this *UUID) UnmarshalText(data []byte) error {
	var err error
	*this, err = ParseBytes(data)
	return err
}

/**
     MarshalText implements the encoding.TextMarshaler interface.
 */

func (this UUID) MarshalText() ([]byte, error) {
	dst := make([]byte, 36)
	err := this.MarshalTextTo(dst)
	return dst, err
}

/**
	Marshal text to preallocated slice
 */

func (this UUID) MarshalTextTo(dst []byte) error {

	if len(dst) < 36 {
		return ErrorWrongLen
	}

	data, err := this.MarshalBinary()
	if err != nil {
		return err
	}

	hex.Encode(dst, data[:4])
	dst[8] = '-'
	hex.Encode(dst[9:13], data[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:18], data[6:8])
	dst[18] = '-'
	hex.Encode(dst[19:23], data[8:10])
	dst[23] = '-'
	hex.Encode(dst[24:], data[10:])
	return nil
}

/**
	UnmarshalJSON implements the json.Unmarshaler interface.
 */

func (this *UUID) UnmarshalJSON(data []byte) error {
	// Ignore null, like in the main JSON package.
	if string(data) == "null" {
		return nil
	}
	// Fractional seconds are handled implicitly by Parse.
	var err error
	*this, err = ParseBytes(data)
	return err
}

/**
	MarshalJSON implements the json.Marshaler interface.
 */

func (this UUID) MarshalJSON() ([]byte, error) {

	jsonVal := make([]byte, 36+2)
	jsonVal[0] = '"'
	jsonVal[37] = '"'
	err := this.MarshalTextTo(jsonVal[1:37])

	return jsonVal, err
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

func (this UUID) String() string {
	dst, _  := this.MarshalText()
	return string(dst)
}

func (this UUID) URN() string {
	return "urn:uuid:" + this.String()
}

func (v Version) String() string {
	return fmt.Sprintf("UUID_V%d", v)
}

func (v Variant) String() string {
	switch v {
	case IETF:
		return "RFC4122"
	case NCSReserved:
		return "NCSBackwardCompatibility"
	case MicrosoftReserved:
		return "Microsoft"
	case FutureReserved:
		return "Future"
	}
	return fmt.Sprintf("BadVariant%d", int(v))
}




