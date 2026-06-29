// Package frame реализует кодирование и декодирование бинарного wire-протокола
// мультипутевой сессии: общий заголовок (Header), фреймы данных (DataFrame),
// кумулятивные ACK с SACK-блоками (AckFrame) и набор control-фреймов
// (Ping/Pong/PathAdd/PathRemove/Close/Pad).
//
// Формат не поддерживает forward-compatible пропуск неизвестных типов фреймов:
// общего поля "длина тела" в заголовке нет (экономия байт на самых частых
// control-фреймах), поэтому встреча неизвестного FrameType — фатальная ошибка
// парсинга потока для данного сабфлоу (см. ErrUnknownFrameType). Версионирование
// протокола, если потребуется, должно решаться на уровне handshake до начала
// обмена фреймами, а не внутри этого пакета.
package frame

import (
	"errors"
	"io"

	"github.com/whicu/viaz/frame/varint"
)

// Ошибки, возвращаемые при кодировании и декодировании фреймов.
var (
	// ErrInvalidFlags возвращается, когда в Header.Flags выставлены биты за
	// пределами FlagsMask (4 младших бита первого байта) — такие биты при
	// упаковке "протекли" бы в пространство Type и испортили его у получателя.
	ErrInvalidFlags = errors.New("frame: invalid flags, bits leak into type space")

	// ErrTypeMismatch возвращается, когда Header.Type не совпадает с типом,
	// который сообщает сама структура фрейма через Frame.Type().
	ErrTypeMismatch = errors.New("frame: type mismatch between header and struct")

	// ErrPiggybackNotApplicable возвращается, когда FlagAckPiggyback выставлен
	// на фрейме типа, отличного от TypeData — флаг имеет смысл только для
	// DataFrame, где он сигнализирует о хвостовой ACK-секции после payload.
	ErrPiggybackNotApplicable = errors.New("frame: ack piggyback flag is only applicable to data frames")

	// ErrInvalidSackLength возвращается, если SackBlock.Length == 0. Блок
	// нулевой длины не несёт информации и создаёт неоднозначность с Gap
	// следующего блока при delta-кодировании.
	ErrInvalidSackLength = errors.New("frame: sack block length cannot be zero")

	// ErrInvalidSackOrder возвращается, если вычисленные абсолютные диапазоны
	// SACK-блоков не монотонно возрастают, пересекаются, либо Gap/Length
	// настолько велики, что переполняют uint64 при сложении.
	ErrInvalidSackOrder = errors.New("frame: sack blocks must be monotonically increasing and non-overlapping")

	// ErrTooManySackBlocks возвращается, когда заявленное blocksCount
	// превышает MaxSackBlocks — защита от OOM через фальшиво большое
	// значение count в ACK-фрейме, присланное до проверки фактического
	// размера буфера.
	ErrTooManySackBlocks = errors.New("frame: sack blocks count exceeds MaxSackBlocks limit")

	// ErrEmptyPayload возвращается для DataFrame с пустым Payload. FIN
	// передаётся отдельным флагом (FlagFin), а не пустым DATA-фреймом —
	// иначе появляется бессмысленный класс "фреймов без данных".
	ErrEmptyPayload = errors.New("frame: data frame payload length cannot be zero")

	// ErrMissingPiggybackAck возвращается, когда FlagAckPiggyback выставлен
	// в заголовке, но DataFrame.PiggybackAck == nil.
	ErrMissingPiggybackAck = errors.New("frame: ack piggyback flag set but PiggybackAck is nil")

	// ErrPiggybackFlagMissing возвращается, когда DataFrame.PiggybackAck
	// заполнен, но FlagAckPiggyback не выставлен в заголовке — без этого
	// флага получатель не будет пытаться парсить хвостовую ACK-секцию, и
	// она будет молча потеряна при сериализации.
	ErrPiggybackFlagMissing = errors.New("frame: PiggybackAck is populated but FlagAckPiggyback is missing in header flags")
)

// MaxSackBlocks — жёсткий потолок количества SACK-блоков в одном ACK-фрейме.
// Защищает decodeAckFields от DoS через раздутое значение blocksCount,
// присланное до того, как декодер успел сверить его с реальным размером
// буфера. 256 блоков — с большим запасом покрывает любой реалистичный паттерн
// потерь/reordering для окна reorder-буфера разумного размера.
const MaxSackBlocks = 256

// EncodeFrame сериализует заголовок h и тело фрейма f, дописывая байты в dst,
// и возвращает результирующий слайс. dst может быть переиспользуемым буфером
// с нулевой длиной (например, через append-growth паттерн) — EncodeFrame
// не делает предположений о его текущей длине, только дописывает в конец.
//
// Возвращает ErrInvalidFlags, ErrTypeMismatch, ErrPiggybackNotApplicable,
// ErrEmptyPayload, ErrMissingPiggybackAck, ErrPiggybackFlagMissing,
// ErrInvalidSackLength, ErrInvalidSackOrder или ошибку varint.Append
// (ErrValueTooLarge), если переданные данные нарушают любой из инвариантов
// протокола. При ошибке возвращаемый слайс — nil, dst не считается частично
// валидным.
func EncodeFrame(dst []byte, h Header, f Frame) ([]byte, error) {
	// ИНВАРИАНТ: флаги не должны выходить за рамки 4 младших бит первого байта.
	if h.Flags&^FlagsMask != 0 {
		return nil, ErrInvalidFlags
	}

	// ИНВАРИАНТ: тип в заголовке должен строго соответствовать типу структуры.
	if h.Type != f.Type() {
		return nil, ErrTypeMismatch
	}

	hasPiggybackFlag := h.Flags&FlagAckPiggyback != 0

	// ИНВАРИАНТ: пигибэк-флаг осмыслен только для DATA — на любом другом типе
	// фрейма это ошибка вызывающего кода, а не молчаливый no-op.
	if hasPiggybackFlag && h.Type != TypeData {
		return nil, ErrPiggybackNotApplicable
	}

	// Упаковываем Type и Flags в один байт: 4 старших бита — тип, 4 младших — флаги.
	firstByte := (uint8(h.Type) << 4) | uint8(h.Flags)
	dst = append(dst, firstByte)

	var err error
	dst, err = varint.Append(dst, h.StreamID)
	if err != nil {
		return nil, err
	}

	switch frame := f.(type) {
	case *DataFrame:
		// ИНВАРИАНТ: пустой payload запрещён.
		if len(frame.Payload) == 0 {
			return nil, ErrEmptyPayload
		}

		// СТРОГАЯ ДВУСТОРОННЯЯ ВАЛИДАЦИЯ PIGGYBACK-ACK — выполняется ДО того,
		// как что-либо записано в dst дальше StreamID, чтобы не тратить работу
		// на сериализацию Seq/Payload при заведомо невалидном вызове.
		if hasPiggybackFlag && frame.PiggybackAck == nil {
			return nil, ErrMissingPiggybackAck
		}
		if !hasPiggybackFlag && frame.PiggybackAck != nil {
			return nil, ErrPiggybackFlagMissing
		}

		dst, err = varint.Append(dst, frame.Seq)
		if err != nil {
			return nil, err
		}

		dst, err = varint.Append(dst, uint64(len(frame.Payload)))
		if err != nil {
			return nil, err
		}

		dst = append(dst, frame.Payload...)

		// На проводе PiggybackAck идёт строго ПОСЛЕ Payload — AckFrame
		// самодостаточен по длине через свой blocksCount, тогда как Payload
		// требует знать длину заранее (varint length перед байтами).
		if hasPiggybackFlag {
			dst, err = appendAckFields(dst, frame.PiggybackAck)
			if err != nil {
				return nil, err
			}
		}

	case *AckFrame:
		dst, err = appendAckFields(dst, frame)
		if err != nil {
			return nil, err
		}

	case *PingFrame, *PongFrame, *PathAddFrame, *PathRemoveFrame, *CloseFrame:
		// Текущая версия протокола: эти типы не несут полей сверх Header.
		// Поля появятся точечно в Фазах 3/5, когда определится их реальная
		// потребность (см. roadmap) — заранее гадать состав сейчас не нужно.

	case *PadFrame:
		dst, err = varint.Append(dst, uint64(len(frame.Payload)))
		if err != nil {
			return nil, err
		}
		dst = append(dst, frame.Payload...)

	default:
		return nil, ErrUnknownFrameType
	}

	return dst, nil
}

// appendAckFields сериализует CumAck и SACK-блоки в формате delta-кодирования
// (gap/length), общем для самостоятельного AckFrame и хвостовой piggyback-секции
// внутри DataFrame. Использует ту же half-open семантику и те же проверки
// монотонности/overflow, что и decodeAckFields — инвариант должен ловиться
// локально при кодировании, а не только постфактум на удалённой стороне при
// декодировании.
func appendAckFields(dst []byte, ack *AckFrame) ([]byte, error) {
	var err error
	dst, err = varint.Append(dst, ack.CumAck)
	if err != nil {
		return nil, err
	}

	dst, err = varint.Append(dst, uint64(len(ack.Blocks)))
	if err != nil {
		return nil, err
	}

	// currentEnd — эксклюзивная верхняя граница подтверждённого пространства,
	// в той же системе координат, что AckFrame.CumAck. Зеркало проверки,
	// которая выполняется в decodeAckFields, чтобы поймать некорректные
	// Gap/Length значения локально, до отправки на провод.
	currentEnd := ack.CumAck

	for _, block := range ack.Blocks {
		if err := validateSackBlock(currentEnd, block); err != nil {
			return nil, err
		}

		dst, err = varint.Append(dst, block.Gap)
		if err != nil {
			return nil, err
		}
		dst, err = varint.Append(dst, block.Length)
		if err != nil {
			return nil, err
		}

		currentEnd = currentEnd + block.Gap + block.Length
	}
	return dst, nil
}

// validateSackBlock проверяет блок относительно текущей эксклюзивной верхней
// границы подтверждённого пространства currentEnd:
//   - Length не может быть нулевой (ErrInvalidSackLength);
//   - Gap/Length не должны переполнять uint64 при сложении, и результирующий
//     диапазон обязан лежать после currentEnd без пересечения (ErrInvalidSackOrder).
//
// Используется и при кодировании (appendAckFields), и при декодировании
// (decodeAckFields) — один источник истины для инварианта вместо двух копий
// логики, которые могли бы рассинхронизироваться.
func validateSackBlock(currentEnd uint64, block SackBlock) error {
	if block.Length == 0 {
		return ErrInvalidSackLength
	}

	start := currentEnd + block.Gap
	if start < currentEnd {
		return ErrInvalidSackOrder
	}

	end := start + block.Length
	if end < start {
		return ErrInvalidSackOrder
	}

	return nil
}

// DecodeFrame парсит один фрейм из входящего байтового слайса src.
// Возвращает разобранный Header, тело фрейма как Frame, количество байт,
// фактически вычитанных из src, и ошибку.
//
// При ошибке возвращаемый Frame — nil, а количество байт — 0; src не считается
// частично разобранным (вызывающий код не должен пытаться "продолжить" с
// какого-либо смещения после ошибки — см. ErrUnknownFrameType).
//
// ⚠️ КОНТРАКТ ВЛАДЕНИЯ ПАМЯТЬЮ (memory ownership):
// В целях производительности (zero-allocation) возвращаемые слайсы внутри
// фреймов (DataFrame.Payload, PadFrame.Payload) — это прямые срезы (алиасы)
// исходного буфера src, не копии.
//
// Вызывающий код ОБЯЗАН соблюдать:
//  1. src нельзя переиспользовать (например, передавать обратно в
//     net.Conn.Read() или возвращать в sync.Pool), пока возвращённый Frame
//     полностью обработан и не удержан где-либо далее.
//  2. Если Frame сохраняется в долгоживущую структуру (например, в reorder-
//     буфер Фазы 2, ожидая заполнения "дырки" в последовательности) —
//     вызывающий код ОБЯЗАН скопировать Payload в независимую область памяти
//     перед сохранением. Иначе последующее чтение в src молча испортит уже
//     "сохранённые" данные — баг, зависящий от тайминга и паттерна потерь,
//     крайне тяжело локализуемый постфактум.
func DecodeFrame(src []byte) (Header, Frame, int, error) {
	if len(src) == 0 {
		return Header{}, nil, 0, io.EOF
	}

	// Разбираем bit-packed первый байт: 4 старших бита — тип, 4 младших — флаги.
	fType := FrameType((src[0] & TypeMASK) >> 4)
	flags := Flags(src[0] & uint8(FlagsMask))
	idx := 1

	streamID, n, err := varint.Decode(src[idx:])
	if err != nil {
		return Header{}, nil, 0, err
	}
	idx += n

	header := Header{
		Type:     fType,
		Flags:    flags,
		StreamID: streamID,
	}

	switch fType {
	case TypeData:
		df := &DataFrame{}

		seq, n, err := varint.Decode(src[idx:])
		if err != nil {
			return header, nil, 0, err
		}
		idx += n
		df.Seq = seq

		pLen, n, err := varint.Decode(src[idx:])
		if err != nil {
			return header, nil, 0, err
		}
		idx += n

		// ИНВАРИАНТ: длина Payload не может быть 0.
		if pLen == 0 {
			return header, nil, 0, ErrEmptyPayload
		}

		if uint64(len(src[idx:])) < pLen {
			return header, nil, 0, io.ErrUnexpectedEOF
		}

		// Алиасинг src без аллокации — см. контракт владения памятью выше.
		df.Payload = src[idx : idx+int(pLen)]
		idx += int(pLen)

		// Попутный ACK, если выставлен флаг, парсится строго после Payload.
		if flags&FlagAckPiggyback != 0 {
			ack, n, err := decodeAckFields(src[idx:])
			if err != nil {
				return header, nil, 0, err
			}
			idx += n
			df.PiggybackAck = ack
		}

		return header, df, idx, nil

	case TypeAck:
		ack, n, err := decodeAckFields(src[idx:])
		if err != nil {
			return header, nil, 0, err
		}
		idx += n
		return header, ack, idx, nil

	case TypePing:
		return header, &PingFrame{}, idx, nil

	case TypePong:
		return header, &PongFrame{}, idx, nil

	case TypePathAdd:
		return header, &PathAddFrame{}, idx, nil

	case TypePathRemove:
		return header, &PathRemoveFrame{}, idx, nil

	case TypeClose:
		return header, &CloseFrame{}, idx, nil

	case TypePad:
		padLen, n, err := varint.Decode(src[idx:])
		if err != nil {
			return header, nil, 0, err
		}
		idx += n

		if uint64(len(src[idx:])) < padLen {
			return header, nil, 0, io.ErrUnexpectedEOF
		}

		pf := &PadFrame{Payload: src[idx : idx+int(padLen)]}
		idx += int(padLen)
		return header, pf, idx, nil

	default:
		// Поле "общая длина тела" отсутствует в заголовке (см. doc пакета),
		// поэтому неизвестный Type делает дальнейший сдвиг по потоку
		// невозможным — это фатальная ошибка парсинга для текущего сабфлоу,
		// а не "пропускаемый" неизвестный фрейм.
		return header, nil, 0, ErrUnknownFrameType
	}
}

// decodeAckFields десериализует CumAck и SACK-блоки в формате delta-кодирования
// из src, начиная с позиции 0 относительно переданного слайса. Возвращает
// разобранный *AckFrame, количество вычитанных байт и ошибку.
//
// Защищено от DoS/OOM через фальшиво большое blocksCount: значение сверяется
// с MaxSackBlocks и с реальным размером буфера ДО вызова make() — заявленное
// количество блоков не может привести к аллокации, для которой физически нет
// данных в src.
func decodeAckFields(src []byte) (*AckFrame, int, error) {
	idx := 0

	cumAck, n, err := varint.Decode(src[idx:])
	if err != nil {
		return nil, 0, err
	}
	idx += n

	blocksCount, n, err := varint.Decode(src[idx:])
	if err != nil {
		return nil, 0, err
	}
	idx += n

	// ЗАЩИТА ОТ DoS (шаг 1): верхний логический предел количества блоков.
	if blocksCount > MaxSackBlocks {
		return nil, 0, ErrTooManySackBlocks
	}

	// ЗАЩИТА ОТ DoS (шаг 2): минимальный размер блока на проводе — 2 байта
	// (1 байт Gap + 1 байт Length в лучшем случае). Если заявленный
	// blocksCount требует больше байт, чем физически есть в src — отправитель
	// либо врёт, либо данные ещё не полностью пришли по сети; в обоих случаях
	// make() ниже не должен быть вызван до этой проверки.
	if uint64(len(src[idx:])) < blocksCount*2 {
		return nil, 0, io.ErrUnexpectedEOF
	}

	ack := &AckFrame{
		CumAck: cumAck,
		Blocks: make([]SackBlock, blocksCount),
	}

	// currentEnd — эксклюзивная верхняя граница подтверждённого пространства,
	// см. doc-комментарий AckFrame для общей системы координат.
	currentEnd := cumAck

	for i := uint64(0); i < blocksCount; i++ {
		gap, n, err := varint.Decode(src[idx:])
		if err != nil {
			return nil, 0, err
		}
		idx += n

		length, n, err := varint.Decode(src[idx:])
		if err != nil {
			return nil, 0, err
		}
		idx += n

		block := SackBlock{Gap: gap, Length: length}
		if err := validateSackBlock(currentEnd, block); err != nil {
			return nil, 0, err
		}

		ack.Blocks[i] = block
		currentEnd = currentEnd + gap + length
	}

	return ack, idx, nil
}
