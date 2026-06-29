package varint_test

import (
	"bytes"
	"io"
	"math"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"pgregory.net/rapid"

	"github.com/whicu/viaz/frame/varint"
)

const (
	maxVarInt1 = 0x3F
	maxVarInt2 = 0x3FFF
	maxVarInt4 = 0x3FFFFFFF
	maxVarInt8 = 0x3FFFFFFFFFFFFFFF
)

var _ = Describe("Varint", func() {

	DescribeTable("RoundTrip encoding and decoding",
		func(val uint64, expectedWidth int) {
			buf, err := varint.Append(nil, val)
			Expect(err).NotTo(HaveOccurred())
			Expect(buf).To(HaveLen(expectedWidth))

			valLen, err := varint.Len(val)
			Expect(err).NotTo(HaveOccurred())
			Expect(valLen).To(Equal(expectedWidth))

			decoded, readBytes, err := varint.Decode(buf)
			Expect(err).NotTo(HaveOccurred())
			Expect(readBytes).To(Equal(expectedWidth))
			Expect(decoded).To(Equal(val))

			var b bytes.Buffer
			n, err := varint.Encode(&b, val)
			Expect(err).NotTo(HaveOccurred())
			Expect(n).To(Equal(expectedWidth))

			streamDecoded, err := varint.Read(&b)
			Expect(err).NotTo(HaveOccurred())
			Expect(streamDecoded).To(Equal(val))
		},

		Entry("Zero", uint64(0), 1),
		Entry("Max 1 Byte", uint64(maxVarInt1), 1),
		Entry("Min 2 Bytes", uint64(maxVarInt1+1), 2),
		Entry("Max 2 Bytes", uint64(maxVarInt2), 2),
		Entry("Min 4 Bytes", uint64(maxVarInt2+1), 4),
		Entry("Max 4 Bytes", uint64(maxVarInt4), 4),
		Entry("Min 8 Bytes", uint64(maxVarInt4+1), 8),
		Entry("Max 8 Bytes", uint64(maxVarInt8), 8),
		Entry("Random 4-byte Value", uint64(123456789), 4),
	)

	Context("when the value exceeds 62 bits max limit", func() {
		const invalidVal = uint64(maxVarInt8 + 1)

		It("should return ErrValueTooLarge on Append", func() {
			_, err := varint.Append(nil, invalidVal)
			Expect(err).To(MatchError(varint.ErrValueTooLarge))
		})

		It("should return ErrValueTooLarge on Encode", func() {
			_, err := varint.Encode(io.Discard, invalidVal)
			Expect(err).To(MatchError(varint.ErrValueTooLarge))
		})

		It("should return ErrValueTooLarge on Len calculation", func() {
			_, err := varint.Len(invalidVal)
			Expect(err).To(MatchError(varint.ErrValueTooLarge))
		})
	})

	Context("when decoding from an incomplete or empty buffer", func() {
		var fullBuf []byte

		BeforeEach(func() {
			var err error
			fullBuf, err = varint.Append(nil, maxVarInt2+1)
			Expect(err).NotTo(HaveOccurred())
			Expect(fullBuf).To(HaveLen(4))
		})

		It("should return io.EOF if the buffer is completely empty", func() {
			_, _, err := varint.Decode([]byte{})
			Expect(err).To(MatchError(io.EOF))

			_, err = varint.Read(bytes.NewReader([]byte{}))
			Expect(err).To(MatchError(io.EOF))
		})

		It("should return io.ErrUnexpectedEOF if the buffer cuts off mid-number", func() {
			for i := 1; i < len(fullBuf); i++ {
				truncated := fullBuf[:i]

				_, _, err := varint.Decode(truncated)
				Expect(err).To(MatchError(io.ErrUnexpectedEOF), "failed at sliced length %d", i)

				br := bytes.NewReader(truncated)
				_, err = varint.Read(br)
				Expect(err).To(MatchError(io.ErrUnexpectedEOF), "failed at stream length %d", i)
			}
		})
	})

	Context("Varint Property-Based Testing", func() {

		It("should successfully roundtrip all valid values up to 62 bits", func() {
			rapid.Check(GinkgoT(), func(t *rapid.T) {
				// Генерируем случайные uint64 строго в валидном диапазоне [0, maxVarInt8]
				val := rapid.Uint64Range(0, maxVarInt8).Draw(t, "valid_uint64")

				// 1. Проверяем консистентность функции расчета длины Len()
				expectedLen, err := varint.Len(val)
				Expect(err).NotTo(HaveOccurred())

				// 2. Проверяем Slice API (Append -> Decode)
				buf, err := varint.Append(nil, val)
				Expect(err).NotTo(HaveOccurred())
				Expect(buf).To(HaveLen(expectedLen))

				decoded, readBytes, err := varint.Decode(buf)
				Expect(err).NotTo(HaveOccurred())
				Expect(readBytes).To(Equal(expectedLen))
				Expect(decoded).To(Equal(val))

				// 3. Проверяем Stream API (Encode -> Read)
				var b bytes.Buffer
				n, err := varint.Encode(&b, val)
				Expect(err).NotTo(HaveOccurred())
				Expect(n).To(Equal(expectedLen))

				streamDecoded, err := varint.Read(&b)
				Expect(err).NotTo(HaveOccurred())
				Expect(streamDecoded).To(Equal(val))
			})
		})

		It("should strictly fail with ErrValueTooLarge for all invalid values (> 62 bits)", func() {
			rapid.Check(GinkgoT(), func(t *rapid.T) {
				// Генерируем "запрещенные" значения от maxVarInt8 + 1 до MaxUint64
				val := rapid.Uint64Range(maxVarInt8+1, math.MaxUint64).Draw(t, "invalid_uint64")

				_, err := varint.Len(val)
				Expect(err).To(MatchError(varint.ErrValueTooLarge))

				_, err = varint.Append(nil, val)
				Expect(err).To(MatchError(varint.ErrValueTooLarge))

				_, err = varint.Encode(io.Discard, val)
				Expect(err).To(MatchError(varint.ErrValueTooLarge))
			})
		})
	})

})
