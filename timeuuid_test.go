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
	"testing"
	"github.com/stretchr/testify/assert"
	"bytes"
	"fmt"
	"time"
	"math/rand"
)

func TestSuit(t *testing.T) {

	println("ZeroUUID=", ZeroUUID.String())

	testTimebasedUUID(t)

	uuid := NewUUID(DCESecurityUUID)
	assert.Equal(t, IETF, uuid.Variant())
	assert.Equal(t, DCESecurityUUID, uuid.Version())

	testRandomlyGeneratedUUID(t)
	testNamebasedUUID(t)

	testTimebasedNamedUUID(t)

	testParser(t)

}

func testParser(t *testing.T) {

	uuid := NewUUID(TimebasedUUID)
	uuid.SetTime(time.Now())
	uuid.SetCounter(rand.Int63())

	comp, err := Parse(uuid.String())
	if err != nil {
		t.Fatal("parse failed ", uuid.String(), err)
	}

	assert.True(t, uuid.Equal(comp))

}

func testTimebasedNamedUUID(t *testing.T) {

	uuid, err := NameUUIDFromBytes([]byte("content"), SHA1NamebasedUUID)
	if err != nil {
		t.Fatal("fail to create name uuid ", err)
	}

	assert.Equal(t, IETF, uuid.Variant())
	assert.Equal(t, SHA1NamebasedUUID, uuid.Version())
	assert.Equal(t, uint64(0x40f06fd77405247), uuid.mostSigBits)
	assert.Equal(t, uint64(0x8d450774f5ba30c5), uuid.leastSigBits)

	uuid.SetUnixTimeMillis(0)
	assert.Equal(t, IETF, uuid.Variant())
	assert.Equal(t, TimebasedUUID, uuid.Version())
	assert.Equal(t, int64(0), uuid.UnixTimeMillis())
	assert.Equal(t, uint64(0x138140001dd211b2), uuid.mostSigBits)
	assert.Equal(t, uint64(0x8d450774f5ba30c5), uuid.leastSigBits)

	assertMarshalText(t, uuid)
	assertMarshalJson(t, uuid)
	assertMarshalBinary(t, uuid)
	assertMarshalSortableBinary(t, uuid)

}

func testTimebasedUUID(t *testing.T) {

	uuid := NewUUID(TimebasedUUID)
	assert.Equal(t, IETF, uuid.Variant())
	assert.Equal(t, TimebasedUUID, uuid.Version())

	assert.Equal(t, int64(0), uuid.Time100Nanos())
	assert.Equal(t, 0, uuid.ClockSequence())
	assert.Equal(t, int64(0), uuid.Node())

	// test MaxNode
	uuid.SetNode(int64(0x0000FFFFFFFFFFFF))
	assert.Equal(t, int64(0x0000FFFFFFFFFFFF), uuid.Node())
	assert.Equal(t, IETF, uuid.Variant())

	// test clear
	uuid.SetNode(0)
	assert.Equal(t, int64(0), uuid.Node())

	// test OverflowNode
	uuid.SetNode(int64(0x0001FFFFFFFFFFFF))
	assert.Equal(t, int64(0x0000FFFFFFFFFFFF), uuid.Node())
	assert.Equal(t, IETF, uuid.Variant())

	// test clear Node
	uuid.SetClockSequence(int(0x3FFF))
	uuid.SetNode(0)
	assert.Equal(t, int64(0), uuid.Node())
	assert.Equal(t, IETF, uuid.Variant())
	uuid.SetClockSequence(int(0))

	// test OverflowClockSequence
	uuid.SetClockSequence(int(0x13FFF))
	assert.Equal(t, int(0x3FFF), uuid.ClockSequence())
	assert.Equal(t, IETF, uuid.Variant())
	uuid.SetClockSequence(0)

	// testMaxClockSequence
	uuid.SetClockSequence(int(0x3FFF))
	assert.Equal(t, int(0x3FFF), uuid.ClockSequence())
	assert.Equal(t, IETF, uuid.Variant())

	// test clear ClockSequence
	uuid.SetNode(int64(0x0000FFFFFFFFFFFF))
	uuid.SetClockSequence(int(0))
	assert.Equal(t, int64(0x0000FFFFFFFFFFFF), uuid.Node())
	assert.Equal(t, IETF, uuid.Variant())
	uuid.SetNode(int64(0))

	// test MaxTime
	uuid.SetTime100Nanos(int64(0x0FFFFFFFFFFFFFFF))
	assert.Equal(t, int64(0x0FFFFFFFFFFFFFFF), uuid.Time100Nanos())
	assert.Equal(t, TimebasedUUID, uuid.Version())

	// test clear MaxTime
	uuid.SetTime100Nanos(0)
	assert.Equal(t, int64(0), uuid.Time100Nanos())
	assert.Equal(t, TimebasedUUID, uuid.Version())

   // test Milliseconds
   uuid.SetUnixTimeMillis(1)
   assert.Equal(t, int64(1), uuid.UnixTimeMillis())

	// test Negative Milliseconds
	uuid.SetUnixTimeMillis(-1)
	assert.Equal(t, int64(-1), uuid.UnixTimeMillis())

	// clear
	uuid.SetUnixTimeMillis(0)
	assert.Equal(t, int64(0), uuid.UnixTimeMillis())

	// test Counter

	uuid = NewUUID(TimebasedUUID)

	uuid.SetMinCounter()
	fmt.Print("min=", uuid.String(), "\n")
	fmt.Printf("counter=%x\n", uuid.Counter())
    binMin := uuid.MarshalSortableBinary()

	uuid.SetMaxCounter()
	fmt.Print("max=", uuid.String(), "\n")
	fmt.Printf("counter=%x\n", uuid.Counter())
	binMax := uuid.MarshalSortableBinary()


	for i := 1; i != 100; i = i + 1 {

		anyNumber := int64(i)
		uuid.SetCounter(anyNumber)

		binLesser := uuid.MarshalSortableBinary()
		uuid.SetCounter(anyNumber+1)

		binGreater := uuid.MarshalSortableBinary()

		assert.True(t, bytes.Compare(binMin, binLesser) < 0, "min failed")
		assert.True(t, bytes.Compare(binLesser, binGreater) < 0, "seq failed")
		assert.True(t, bytes.Compare(binGreater, binMax) < 0, "max failed")
	}

	uuid = NewUUID(TimebasedUUID)

	current := time.Now()

	uuid.SetTime(current)
	cnt := uuid.SetCounter(rand.Int63())

	assert.Equal(t, current.UnixNano() / 100, uuid.Time().UnixNano() / 100)
	assert.Equal(t, cnt, uuid.Counter())

	assertMarshalText(t, uuid)
	assertMarshalJson(t, uuid)
	assertMarshalBinary(t, uuid)
	assertMarshalSortableBinary(t, uuid)

}

func testRandomlyGeneratedUUID(t *testing.T) {

	uuid := NewUUID(RandomlyGeneratedUUID)
	assert.Equal(t, IETF, uuid.Variant())
	assert.Equal(t, RandomlyGeneratedUUID, uuid.Version())

	uuid, err := RandomUUID()

	if err != nil {
		t.Fatal("fail to create random uuid ", err)
	}

	assert.Equal(t, IETF, uuid.Variant())
	assert.Equal(t, RandomlyGeneratedUUID, uuid.Version())

	assertMarshalText(t, uuid)
	assertMarshalJson(t, uuid)
	assertMarshalBinary(t, uuid)
	assertMarshalSortableBinary(t, uuid)

}

func testNamebasedUUID(t *testing.T) {

	uuid := NewUUID(SHA1NamebasedUUID)
	assert.Equal(t, IETF, uuid.Variant())
	assert.Equal(t, SHA1NamebasedUUID, uuid.Version())

	uuid = NewUUID(MD5NamebasedUUID)
	assert.Equal(t, IETF, uuid.Variant())
	assert.Equal(t, MD5NamebasedUUID, uuid.Version())

	uuid, err := NameUUIDFromBytes([]byte("alex"), MD5NamebasedUUID)

	if err != nil {
		t.Fatal("fail to create random uuid ", err)
	}

	assert.Equal(t, IETF, uuid.Variant())
	assert.Equal(t, MD5NamebasedUUID, uuid.Version())
	assert.Equal(t, uint64(0x534b44a19bf13d20), uuid.mostSigBits)
	assert.Equal(t, uint64(0xb71ecc4eb77c572f), uuid.leastSigBits)

	assert.Equal(t, "534b44a1-9bf1-3d20-b71e-cc4eb77c572f", uuid.String())

	assertMarshalText(t, uuid)
	assertMarshalJson(t, uuid)
	assertMarshalBinary(t, uuid)
	assertMarshalSortableBinary(t, uuid)

}

func assertMarshalText(t *testing.T, uuid UUID) {

	var actual UUID
	data, err := uuid.MarshalText()

	if err != nil {
		t.Fatal("fail to MarshalText ", err)
	}

	err = actual.UnmarshalText(data)

	if err != nil {
		t.Fatal("fail to MarshalText ", err)
	}

	assert.Equal(t, uuid.mostSigBits, actual.mostSigBits)
	assert.Equal(t, uuid.leastSigBits, actual.leastSigBits)


}

func assertMarshalJson(t *testing.T, uuid UUID) {

	var actual UUID
	data, err := uuid.MarshalJSON()

	if err != nil {
		t.Fatal("fail to MarshalJson ", err)
	}

	err = actual.UnmarshalJSON(data)

	if err != nil {
		t.Fatal("fail to UnmarshalJson ", err)
	}

	assert.Equal(t, uuid.mostSigBits, actual.mostSigBits)
	assert.Equal(t, uuid.leastSigBits, actual.leastSigBits)


}
func assertMarshalBinary(t *testing.T, uuid UUID) {

	var actual UUID
	data, err := uuid.MarshalBinary()

	if err != nil {
		t.Fatal("fail to MarshalBinary ", err)
	}

	err = actual.UnmarshalBinary(data)

	if err != nil {
		t.Fatal("fail to UnmarshalBinary ", err)
	}

	assert.Equal(t, uuid.mostSigBits, actual.mostSigBits)
	assert.Equal(t, uuid.leastSigBits, actual.leastSigBits)


}

func assertMarshalSortableBinary(t *testing.T, uuid UUID) {

	var actual UUID
	err := actual.UnmarshalSortableBinary(uuid.MarshalSortableBinary())

	if err != nil {
		t.Fatal("fail to UnmarshalSortableBinary ", err)
	}

	assert.Equal(t, uuid.mostSigBits, actual.mostSigBits)
	assert.Equal(t, uuid.leastSigBits, actual.leastSigBits)


}

