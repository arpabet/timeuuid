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
)

func TestSuit(t *testing.T) {

	println("uuid tests")

	testRandomlyGenerated(t)
	testNamebased(t)

}


func testRandomlyGenerated(t *testing.T) {

	uuid, err := RandomUUID()

	if err != nil {
		t.Fatal("fail to create random uuid ", err)
	}

	assert.Equal(t, RFC4122, uuid.Variant())
	assert.Equal(t, RandomlyGeneratedUUID, uuid.Version())

	assertMarshal(t, uuid)
	assertSortableMarshal(t, uuid)
	assertSortableFlip(t, uuid)

}

func testNamebased(t *testing.T) {

	uuid, err := NameUUIDFromBytes([]byte("alex"))

	if err != nil {
		t.Fatal("fail to create random uuid ", err)
	}

	assert.Equal(t, RFC4122, uuid.Variant())
	assert.Equal(t, NamebasedUUID, uuid.Version())
	assert.Equal(t, int64(6001966389298019616), uuid.mostSigBits)
	assert.Equal(t, int64(-5251535477009524945), uuid.leastSigBits)

	assert.Equal(t, "534b44a1-9bf1-3d20-b71e-cc4eb77c572f", uuid.String())

	assertMarshal(t, uuid)
	assertSortableMarshal(t, uuid)
	assertSortableFlip(t, uuid)

}

func assertMarshal(t *testing.T, uuid UUID) {

	var actual UUID
	err := actual.UnmarshalBinary(uuid.MarshalBinary())

	if err != nil {
		t.Fatal("fail to UnmarshalBinary ", err)
	}

	assert.Equal(t, uuid.mostSigBits, actual.mostSigBits)
	assert.Equal(t, uuid.leastSigBits, actual.leastSigBits)


}

func assertSortableMarshal(t *testing.T, uuid UUID) {

	var actual UUID
	err := actual.UnmarshalSortableBinary(uuid.MarshalSortableBinary())

	if err != nil {
		t.Fatal("fail to UnmarshalSortableBinary ", err)
	}

	assert.Equal(t, uuid.mostSigBits, actual.mostSigBits)
	assert.Equal(t, uuid.leastSigBits, actual.leastSigBits)


}

func assertSortableFlip(t *testing.T, uuid UUID) {

	data := uuid.MarshalBinary()
	srt1, _ := FlipToSortable(data)
	srt2 := uuid.MarshalSortableBinary()

	assert.Equal(t, srt1, srt2)

	actual, _ := FlipFromSortable(srt1)
	assert.Equal(t, data, actual)

}