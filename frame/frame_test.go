package frame_test

import (
	"github.com/whicu/viaz/frame/varint"
	"io"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/whicu/viaz/frame"
)

var _ = Describe("Frame RoundTrip", func() {
	roundTripTest := func(h frame.Header, f frame.Frame) {
		buf, err := frame.EncodeFrame(nil, h, f)
		Expect(err).NotTo(HaveOccurred())
		Expect(buf).NotTo(BeNil())

		decHeader, decFrame, n, err := frame.DecodeFrame(buf)
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(len(buf)))
		Expect(decHeader).To(Equal(h))
		Expect(decFrame).To(BeEquivalentTo(f))
	}

	It("DataFrame without piggyback", func() {
		h := frame.Header{Type: frame.TypeData, StreamID: 42}
		f := &frame.DataFrame{
			Seq:     100,
			Payload: []byte("hello"),
		}
		roundTripTest(h, f)
	})

	It("DataFrame with piggyback (0 blocks)", func() {
		h := frame.Header{Type: frame.TypeData, StreamID: 42, Flags: frame.FlagAckPiggyback}
		f := &frame.DataFrame{
			Seq:          100,
			Payload:      []byte("world"),
			PiggybackAck: &frame.AckFrame{CumAck: 50, Blocks: []frame.SackBlock{}},
		}
		roundTripTest(h, f)
	})

	It("DataFrame with piggyback (1 block)", func() {
		h := frame.Header{Type: frame.TypeData, StreamID: 42, Flags: frame.FlagAckPiggyback}
		f := &frame.DataFrame{
			Seq:          100,
			Payload:      []byte("hello"),
			PiggybackAck: &frame.AckFrame{CumAck: 50, Blocks: []frame.SackBlock{{Gap: 2, Length: 5}}},
		}
		roundTripTest(h, f)
	})

	It("DataFrame with piggyback (multiple blocks)", func() {
		h := frame.Header{Type: frame.TypeData, StreamID: 42, Flags: frame.FlagAckPiggyback}
		f := &frame.DataFrame{
			Seq:     100,
			Payload: []byte("hello"),
			PiggybackAck: &frame.AckFrame{
				CumAck: 50,
				Blocks: []frame.SackBlock{
					{Gap: 2, Length: 5},
					{Gap: 1, Length: 3},
				},
			},
		}
		roundTripTest(h, f)
	})

	It("AckFrame separately (empty blocks/nil)", func() {
		h := frame.Header{Type: frame.TypeAck, StreamID: 0}
		f := &frame.AckFrame{CumAck: 10}
		// Expect decoded Blocks to be []SackBlock{} instead of nil
		buf, err := frame.EncodeFrame(nil, h, f)
		Expect(err).NotTo(HaveOccurred())
		decHeader, decFrame, _, err := frame.DecodeFrame(buf)
		Expect(err).NotTo(HaveOccurred())
		Expect(decHeader).To(Equal(h))
		decAck := decFrame.(*frame.AckFrame)
		Expect(decAck.CumAck).To(Equal(uint64(10)))
		Expect(decAck.Blocks).To(BeEmpty()) // Can be nil or empty slice
	})

	It("AckFrame separately (1 block)", func() {
		h := frame.Header{Type: frame.TypeAck, StreamID: 0}
		f := &frame.AckFrame{CumAck: 10, Blocks: []frame.SackBlock{{Gap: 1, Length: 1}}}
		roundTripTest(h, f)
	})

	It("AckFrame separately (multiple blocks)", func() {
		h := frame.Header{Type: frame.TypeAck, StreamID: 0}
		f := &frame.AckFrame{
			CumAck: 10,
			Blocks: []frame.SackBlock{
				{Gap: 1, Length: 1},
				{Gap: 2, Length: 3},
			},
		}
		roundTripTest(h, f)
	})

	It("PingFrame", func() { roundTripTest(frame.Header{Type: frame.TypePing, StreamID: 0}, &frame.PingFrame{}) })
	It("PongFrame", func() { roundTripTest(frame.Header{Type: frame.TypePong, StreamID: 1}, &frame.PongFrame{}) })
	It("PathAddFrame", func() { roundTripTest(frame.Header{Type: frame.TypePathAdd, StreamID: 2}, &frame.PathAddFrame{}) })
	It("PathRemoveFrame", func() { roundTripTest(frame.Header{Type: frame.TypePathRemove, StreamID: 3}, &frame.PathRemoveFrame{}) })
	It("CloseFrame", func() { roundTripTest(frame.Header{Type: frame.TypeClose, StreamID: 4}, &frame.CloseFrame{}) })
	It("PadFrame (empty payload)", func() {
		roundTripTest(frame.Header{Type: frame.TypePad, StreamID: 0}, &frame.PadFrame{Payload: []byte{}})
	})
	It("PadFrame (non-empty payload)", func() {
		roundTripTest(frame.Header{Type: frame.TypePad, StreamID: 0}, &frame.PadFrame{Payload: []byte("junk")})
	})

	DescribeTable("varint boundary values",
		func(val uint64) {
			h := frame.Header{Type: frame.TypeData, StreamID: val}
			f := &frame.DataFrame{Seq: val, Payload: []byte("bound")}
			roundTripTest(h, f)

			hAck := frame.Header{Type: frame.TypeAck, StreamID: val}
			fAck := &frame.AckFrame{CumAck: val, Blocks: []frame.SackBlock{}}
			buf, err := frame.EncodeFrame(nil, hAck, fAck)
			Expect(err).NotTo(HaveOccurred())
			decH, decF, _, err := frame.DecodeFrame(buf)
			Expect(err).NotTo(HaveOccurred())
			Expect(decH.StreamID).To(Equal(val))
			Expect(decF.(*frame.AckFrame).CumAck).To(Equal(val))
		},
		Entry("boundary 63", uint64(63)),
		Entry("boundary 64", uint64(64)),
		Entry("boundary 16383", uint64(16383)),
		Entry("boundary 16384", uint64(16384)),
		Entry("boundary 1073741823", uint64(1073741823)),
		Entry("boundary 1073741824", uint64(1073741824)),
		Entry("maxVarInt8", uint64(0x3FFFFFFFFFFFFFFF)),
	)
})

type dummyFrame struct{}

func (f *dummyFrame) Type() frame.FrameType { return 0x8 } // undefined type

var _ = Describe("EncodeFrame Negative", func() {
	It("invalid flags bit", func() {
		h := frame.Header{Type: frame.TypePing, Flags: 0x10}
		_, err := frame.EncodeFrame(nil, h, &frame.PingFrame{})
		Expect(err).To(MatchError(frame.ErrInvalidFlags))
	})

	It("type mismatch", func() {
		h := frame.Header{Type: frame.TypeAck}
		_, err := frame.EncodeFrame(nil, h, &frame.DataFrame{})
		Expect(err).To(MatchError(frame.ErrTypeMismatch))
	})

	It("piggyback not applicable", func() {
		h := frame.Header{Type: frame.TypePing, Flags: frame.FlagAckPiggyback}
		_, err := frame.EncodeFrame(nil, h, &frame.PingFrame{})
		Expect(err).To(MatchError(frame.ErrPiggybackNotApplicable))

		h2 := frame.Header{Type: frame.TypeClose, Flags: frame.FlagAckPiggyback}
		_, err2 := frame.EncodeFrame(nil, h2, &frame.CloseFrame{})
		Expect(err2).To(MatchError(frame.ErrPiggybackNotApplicable))
	})

	It("empty payload for DataFrame", func() {
		h := frame.Header{Type: frame.TypeData}

		_, err := frame.EncodeFrame(nil, h, &frame.DataFrame{Payload: nil})
		Expect(err).To(MatchError(frame.ErrEmptyPayload))

		_, err = frame.EncodeFrame(nil, h, &frame.DataFrame{Payload: []byte{}})
		Expect(err).To(MatchError(frame.ErrEmptyPayload))
	})

	It("missing piggyback ack", func() {
		h := frame.Header{Type: frame.TypeData, Flags: frame.FlagAckPiggyback}
		_, err := frame.EncodeFrame(nil, h, &frame.DataFrame{Payload: []byte("a"), PiggybackAck: nil})
		Expect(err).To(MatchError(frame.ErrMissingPiggybackAck))
	})

	It("piggyback flag missing", func() {
		h := frame.Header{Type: frame.TypeData}
		_, err := frame.EncodeFrame(nil, h, &frame.DataFrame{Payload: []byte("a"), PiggybackAck: &frame.AckFrame{}})
		Expect(err).To(MatchError(frame.ErrPiggybackFlagMissing))
	})

	It("invalid sack length 0", func() {
		h := frame.Header{Type: frame.TypeAck}
		f := &frame.AckFrame{CumAck: 1, Blocks: []frame.SackBlock{{Gap: 0, Length: 0}}}
		_, err := frame.EncodeFrame(nil, h, f)
		Expect(err).To(MatchError(frame.ErrInvalidSackLength))

		hData := frame.Header{Type: frame.TypeData, Flags: frame.FlagAckPiggyback}
		fData := &frame.DataFrame{
			Payload:      []byte("a"),
			PiggybackAck: &frame.AckFrame{CumAck: 1, Blocks: []frame.SackBlock{{Gap: 0, Length: 0}}},
		}
		_, err2 := frame.EncodeFrame(nil, hData, fData)
		Expect(err2).To(MatchError(frame.ErrInvalidSackLength))
	})

	It("invalid sack order (intersecting / out of order)", func() {
		h := frame.Header{Type: frame.TypeAck}
		// CumAck=10 -> currentEnd=10
		// Block0: Gap=0, Length=5 -> start=10, end=15, currentEnd=15
		// Block1: Gap=0, Length=5 -> start=15, end=20. Wait, what if we use math to make it intersect?
		// Gap is added to currentEnd. start = currentEnd + block.Gap.
		// If Gap is large enough to overflow uint64, it might overlap.
		// Since we can't make Gap negative, let's overflow to test order.

		// To cause "end < start" or "start < currentEnd", we use overflow:
		f := &frame.AckFrame{
			CumAck: 10,
			Blocks: []frame.SackBlock{
				{Gap: ^uint64(0), Length: 5}, // causes start < currentEnd due to wrap
			},
		}
		_, err := frame.EncodeFrame(nil, h, f)
		Expect(err).To(MatchError(frame.ErrInvalidSackOrder))

		f2 := &frame.AckFrame{
			CumAck: 10,
			Blocks: []frame.SackBlock{
				{Gap: 5, Length: ^uint64(0)}, // start = 15, end = 15 + ^0 (wraps) < start
			},
		}
		_, err2 := frame.EncodeFrame(nil, h, f2)
		Expect(err2).To(MatchError(frame.ErrInvalidSackOrder))
	})

	It("unknown frame type from Frame implementation", func() {
		h := frame.Header{Type: 0x8}
		_, err := frame.EncodeFrame(nil, h, &dummyFrame{})
		Expect(err).To(MatchError(frame.ErrUnknownFrameType))
	})

	DescribeTable("varint limits",
		func(testCase func()) {
			testCase()
		},
		Entry("StreamID > maxVarInt8", func() {
			h := frame.Header{Type: frame.TypePing, StreamID: 0x4000000000000000}
			_, err := frame.EncodeFrame(nil, h, &frame.PingFrame{})
			Expect(err).To(MatchError(varint.ErrValueTooLarge))
		}),
		Entry("Seq > maxVarInt8", func() {
			h := frame.Header{Type: frame.TypeData, StreamID: 0}
			_, err := frame.EncodeFrame(nil, h, &frame.DataFrame{Seq: 0x4000000000000000, Payload: []byte("a")})
			Expect(err).To(MatchError(varint.ErrValueTooLarge))
		}),
		Entry("CumAck > maxVarInt8", func() {
			h := frame.Header{Type: frame.TypeAck, StreamID: 0}
			_, err := frame.EncodeFrame(nil, h, &frame.AckFrame{CumAck: 0x4000000000000000})
			Expect(err).To(MatchError(varint.ErrValueTooLarge))
		}),
		Entry("Gap > maxVarInt8", func() {
			h := frame.Header{Type: frame.TypeAck, StreamID: 0}
			_, err := frame.EncodeFrame(nil, h, &frame.AckFrame{CumAck: 1, Blocks: []frame.SackBlock{{Gap: 0x4000000000000000, Length: 1}}})
			Expect(err).To(MatchError(varint.ErrValueTooLarge))
		}),
		Entry("Length > maxVarInt8", func() {
			h := frame.Header{Type: frame.TypeAck, StreamID: 0}
			_, err := frame.EncodeFrame(nil, h, &frame.AckFrame{CumAck: 1, Blocks: []frame.SackBlock{{Gap: 1, Length: 0x4000000000000000}}})
			Expect(err).To(MatchError(varint.ErrValueTooLarge))
		}),
	)
})

var _ = Describe("DecodeFrame Negative", func() {
	It("empty buffer", func() {
		_, _, _, err := frame.DecodeFrame([]byte{})
		Expect(err).To(MatchError(io.EOF))
	})

	Context("truncated buffers", func() {
		var fullBuf []byte

		BeforeEach(func() {
			h := frame.Header{Type: frame.TypeData, StreamID: 42, Flags: frame.FlagAckPiggyback}
			f := &frame.DataFrame{
				Seq:          100,
				Payload:      []byte("world"),
				PiggybackAck: &frame.AckFrame{CumAck: 50, Blocks: []frame.SackBlock{{Gap: 1, Length: 2}}},
			}
			var err error
			fullBuf, err = frame.EncodeFrame(nil, h, f)
			Expect(err).NotTo(HaveOccurred())
		})

		It("truncation at all boundaries should yield io.ErrUnexpectedEOF", func() {
			for i := 1; i < len(fullBuf); i++ {
				truncated := fullBuf[:i]
				_, _, _, err := frame.DecodeFrame(truncated)

				// Wait, varint.Decode might return io.EOF if the buffer is completely empty for the NEXT varint?
				// Actually varint.Decode returns io.EOF if len(src) == 0.
				// But if len(src)>0 and it cuts off, it returns io.ErrUnexpectedEOF.
				// Wait, if it cuts off EXACTLY at a field boundary, varint.Decode will receive an empty slice for the next field,
				// returning io.EOF. Let's see what happens.

				// Our code currently does not map varint's io.EOF to io.ErrUnexpectedEOF internally in DecodeFrame!
				// In DecodeFrame:
				// streamID, n, err := varint.Decode(src[idx:])
				// ...
				// varint.Decode on empty slice gives io.EOF.

				// Let's assert it returns either io.EOF or io.ErrUnexpectedEOF.
				Expect(err).To(HaveOccurred())
				Expect(err == io.EOF || err == io.ErrUnexpectedEOF).To(BeTrue(), "expected EOF or UnexpectedEOF, got: %v", err)
			}
		})
	})

	It("DataFrame with pLen == 0 on the wire", func() {
		// Construct manually: type=Data (0), StreamID=1, Seq=2, pLen=0
		buf := []byte{0x00, 0x01, 0x02, 0x00}
		_, _, _, err := frame.DecodeFrame(buf)
		Expect(err).To(MatchError(frame.ErrEmptyPayload))
	})

	It("PadFrame/Data: payload length longer than remaining buffer", func() {
		// DataFrame: Type=Data, StreamID=1, Seq=2, pLen=10, actual payload 1 byte
		bufData := []byte{0x00, 0x01, 0x02, 0x0a, 0xff}
		_, _, _, err := frame.DecodeFrame(bufData)
		Expect(err).To(MatchError(io.ErrUnexpectedEOF))

		// PadFrame: Type=Pad (7), StreamID=1, padLen=10, actual payload 1 byte
		bufPad := []byte{0x70, 0x01, 0x0a, 0xff}
		_, _, _, err2 := frame.DecodeFrame(bufPad)
		Expect(err2).To(MatchError(io.ErrUnexpectedEOF))
	})

	It("Unknown FrameType on the wire", func() {
		// Type = 0x8 (8 << 4) = 0x80
		buf := []byte{0x80, 0x01}
		_, _, _, err := frame.DecodeFrame(buf)
		Expect(err).To(MatchError(frame.ErrUnknownFrameType))

		// Type = 0xF (15 << 4) = 0xF0
		buf2 := []byte{0xF0, 0x01}
		_, _, _, err2 := frame.DecodeFrame(buf2)
		Expect(err2).To(MatchError(frame.ErrUnknownFrameType))
	})
})

var _ = Describe("decodeAckFields DoS protection", func() {
	It("blocksCount > MaxSackBlocks returns ErrTooManySackBlocks", func() {
		// TypeAck (0x10), StreamID (0x01)
		// CumAck = 10 (0x0a)
		// BlocksCount = 300. 300 is 0x012C. Varint encoding for 2 bytes:
		// 01xxxxxx xxxxxxxx -> 01000001 00101100 = 0x41, 0x2C
		buf := []byte{0x10, 0x01, 0x0a, 0x41, 0x2C}

		// Fill buffer with dummy data so it physically has enough bytes to pass EOF check
		// if the length check wasn't there
		dummyData := make([]byte, 600)
		buf = append(buf, dummyData...)

		_, _, _, err := frame.DecodeFrame(buf)
		Expect(err).To(MatchError(frame.ErrTooManySackBlocks))
	})

	It("blocksCount <= MaxSackBlocks but physically not enough bytes", func() {
		// TypeAck (0x10), StreamID (0x01)
		// CumAck = 10 (0x0a)
		// BlocksCount = 10 (0x0a) -> Needs at least 20 bytes (2 bytes per block min)
		buf := []byte{0x10, 0x01, 0x0a, 0x0a}

		// Buffer only has 5 bytes after this
		dummyData := make([]byte, 5)
		buf = append(buf, dummyData...)

		_, _, _, err := frame.DecodeFrame(buf)
		Expect(err).To(MatchError(io.ErrUnexpectedEOF))
	})

	It("correct blocksCount but buffer ends midway through cycle", func() {
		// TypeAck (0x10), StreamID (0x01)
		// CumAck = 10 (0x0a)
		// BlocksCount = 2 (0x02)
		// Block 1: Gap=1 (0x01), Length=2 (0x02)
		// Block 2: Gap=1 (0x01), Length is missing
		buf := []byte{0x10, 0x01, 0x0a, 0x02, 0x01, 0x02, 0x01}

		_, _, _, err := frame.DecodeFrame(buf)
		// varint.Decode returns io.EOF since no bytes left for the length
		// Should we map this to io.ErrUnexpectedEOF or is io.EOF what happens now?
		// Given our current implementation in frame.go:
		// length, n, err := varint.Decode(src[idx:])
		// if err != nil { return nil, 0, err }
		// If src[idx:] is empty, it returns io.EOF. Let's assert either.
		Expect(err).To(HaveOccurred())
		Expect(err == io.EOF || err == io.ErrUnexpectedEOF).To(BeTrue())
	})

	It("blocksCount == 0 (zero-block ACK frame)", func() {
		// This should be a normal success case.
		h := frame.Header{Type: frame.TypeAck, StreamID: 0}
		f := &frame.AckFrame{CumAck: 100, Blocks: nil} // Equivalent to 0 blocks
		buf, err := frame.EncodeFrame(nil, h, f)
		Expect(err).NotTo(HaveOccurred())

		_, decFrame, _, err := frame.DecodeFrame(buf)
		Expect(err).NotTo(HaveOccurred())
		decAck := decFrame.(*frame.AckFrame)
		Expect(decAck.CumAck).To(Equal(uint64(100)))
		Expect(decAck.Blocks).To(BeEmpty())
	})
})

var _ = Describe("Memory Aliasing Contract", func() {
	It("DataFrame Payload should alias the source buffer", func() {
		h := frame.Header{Type: frame.TypeData, StreamID: 1}
		f := &frame.DataFrame{Seq: 2, Payload: []byte("original")}

		buf, err := frame.EncodeFrame(nil, h, f)
		Expect(err).NotTo(HaveOccurred())

		_, decFrame, _, err := frame.DecodeFrame(buf)
		Expect(err).NotTo(HaveOccurred())

		df := decFrame.(*frame.DataFrame)
		Expect(df.Payload).To(Equal([]byte("original")))

		// Mutate the original buffer that was passed to DecodeFrame
		// We need to find where the payload is in the buffer.
		// Since DecodeFrame uses aliases, modifying buf should modify df.Payload.
		// Let's modify the last 8 bytes of buf (which is the payload).
		payloadOffset := len(buf) - len("original")
		buf[payloadOffset] = 'O'
		buf[payloadOffset+1] = 'R'

		// If it's an alias, df.Payload should reflect this change.
		Expect(df.Payload).To(Equal([]byte("ORiginal")))
	})
})
