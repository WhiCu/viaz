/*
Package frame реализует кодирование и декодирование целочисленных значений
переменной длины (Varint) в формате протокола QUIC (RFC 9000).

Размер числа (1, 2, 4 или 8 байт) определяется двумя старшими битами (MSB)
самого первого байта. Остальные биты используются для хранения значения.

Схема битовой структуры (Bit Layout):

	Байт 0   Байт 1   Байт 2   Байт 3
	01234567 01234567 01234567 01234567

+--------+
|00xxxxxx|                                       -> 1 байт (макс: 63)
+--------+

+--------+--------+
|01xxxxxx|xxxxxxxx|                              -> 2 байта (макс: 16 383)
+--------+--------+

+--------+--------+--------+--------+
|10xxxxxx|xxxxxxxx|xxxxxxxx|xxxxxxxx|            -> 4 байта (макс: 1 073 741 823)
+--------+--------+--------+--------+

+--------+--------+--------+--------+--------+--------+--------+--------+
|11xxxxxx|xxxxxxxx|xxxxxxxx|xxxxxxxx|xxxxxxxx|xxxxxxxx|xxxxxxxx|xxxxxxxx| -> 8 байт (макс: 4 611 686 018 427 387 903)
+--------+--------+--------+--------+--------+--------+--------+--------+

Где:

	00, 01, 10, 11 — маркеры длины (префиксы).
	x              — биты полезной нагрузки (данные).

При чтении кодек сначала изолирует префикс (first >> 6), чтобы узнать длину,
а затем очищает полезные данные первого байта с помощью маски (first & 0x3F).
*/
package varint

import (
	"errors"
	"io"
)

var (
	ErrValueTooLarge = errors.New("varint: value exceeds 62 bits max limit")
)

const (
	maxVarInt1 = 0x3F               // 63 (6 бит)
	maxVarInt2 = 0x3FFF             // 16383 (14 бит)
	maxVarInt4 = 0x3FFFFFFF         // 1073741823 (30 бит)
	maxVarInt8 = 0x3FFFFFFFFFFFFFFF // 4611686018427387903 (62 бита)
)

func Len(i uint64) (int, error) {
	if i <= maxVarInt1 {
		return 1, nil
	}
	if i <= maxVarInt2 {
		return 2, nil
	}
	if i <= maxVarInt4 {
		return 4, nil
	}
	if i <= maxVarInt8 {
		return 8, nil
	}
	return 0, ErrValueTooLarge
}

func Append(dst []byte, i uint64) ([]byte, error) {
	t, err := Len(i)
	if err != nil {
		return nil, err
	}
	switch t {
	case 1:
		return append(dst, uint8(i)), nil
	case 2:
		return append(dst, uint8(i>>8)|0x40, uint8(i)), nil
	case 4:
		return append(dst, uint8(i>>24)|0x80, uint8(i>>16), uint8(i>>8), uint8(i)), nil
	case 8:
		return append(dst,
			uint8(i>>56)|0xc0, uint8(i>>48), uint8(i>>40), uint8(i>>32),
			uint8(i>>24), uint8(i>>16), uint8(i>>8), uint8(i),
		), nil
	}
	panic("unreachable")
}

func Decode(src []byte) (uint64, int, error) {
	if len(src) == 0 {
		return 0, 0, io.EOF
	}

	first := src[0]
	prefix := first >> 6
	length := 1 << prefix

	if len(src) < length {
		return 0, 0, io.ErrUnexpectedEOF
	}

	switch prefix {
	case 0:
		return uint64(first & 0x3F), 1, nil
	case 1:
		return uint64(first&0x3F)<<8 | uint64(src[1]), 2, nil
	case 2:
		_ = src[3] // Оптимизация компилятора: Bounds Check Elimination
		val := uint64(first&0x3F)<<24 |
			uint64(src[1])<<16 |
			uint64(src[2])<<8 |
			uint64(src[3])
		return val, 4, nil
	default: // case 3
		_ = src[7] // Bounds Check Elimination
		val := uint64(first&0x3F)<<56 |
			uint64(src[1])<<48 |
			uint64(src[2])<<40 |
			uint64(src[3])<<32 |
			uint64(src[4])<<24 |
			uint64(src[5])<<16 |
			uint64(src[6])<<8 |
			uint64(src[7])
		return val, 8, nil
	}
}

func Read(r io.ByteReader) (uint64, error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, err // Если первый байт не прочитался — это может быть легальный io.EOF
	}

	prefix := first >> 6
	switch prefix {
	case 0:
		return uint64(first & 0x3F), nil
	case 1:
		b1, err := r.ReadByte()
		if err != nil {
			return 0, unexpectedEOF(err)
		}
		return uint64(first&0x3F)<<8 | uint64(b1), nil
	case 2:
		b1, err := r.ReadByte()
		if err != nil {
			return 0, unexpectedEOF(err)
		}
		b2, err := r.ReadByte()
		if err != nil {
			return 0, unexpectedEOF(err)
		}
		b3, err := r.ReadByte()
		if err != nil {
			return 0, unexpectedEOF(err)
		}
		return uint64(first&0x3F)<<24 | uint64(b1)<<16 | uint64(b2)<<8 | uint64(b3), nil
	default:
		var res uint64 = uint64(first & 0x3F)
		for range 7 {
			b, err := r.ReadByte()
			if err != nil {
				return 0, unexpectedEOF(err)
			}
			res = (res << 8) | uint64(b)
		}
		return res, nil
	}
}

func Encode(w io.Writer, i uint64) (int, error) {
	var buf [8]byte
	b, err := Append(buf[:0], i)
	if err != nil {
		return 0, err
	}
	return w.Write(b)
}

func unexpectedEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}
