package frame

import (
	"errors"
)

var ErrUnknownFrameType = errors.New("unknown frame type, parsing impossible")

// Frame представляет универсальный интерфейс для всех типов фреймов протокола.
type Frame interface {
	Type() FrameType
}

type FrameType uint8

const (
	// MASK
	TypeMASK uint8 = 0xF0

	// Types
	TypeData       FrameType = 0x0
	TypeAck        FrameType = 0x1
	TypePing       FrameType = 0x2
	TypePong       FrameType = 0x3
	TypePathAdd    FrameType = 0x4
	TypePathRemove FrameType = 0x5
	TypeClose      FrameType = 0x6
	TypePad        FrameType = 0x7
)

type Flags uint8

const (
	FlagFin          Flags = 0x01
	FlagAckPiggyback Flags = 0x02 // Используется для DATA фреймов с попутным ACK

	// FlagsMask — маска валидных бит флагов (4 младших бита первого байта фрейма).
	// Type и Flags упаковываются в один байт на проводе как (Type<<4 | Flags).
	// Encode ДОЛЖЕН проверять Flags&^FlagsMask == 0 перед упаковкой — иначе
	// неучтённый бит флага молча "протечёт" в старшие 4 бита и испортит Type
	// у получателя.
	FlagsMask Flags = 0x0F
)

// Header — общий заголовок, парсится первым для всех типов фреймов.
//
// StreamID валиден для всех типов, но осознанно избыточен для PING/PONG —
// это RTT-зонды уровня сабфлоу (физического пути), а не логического потока,
// и для них StreamID всегда будет 0. Цена решения — 1 лишний байт на PING/PONG,
// выгода — единый код парсинга заголовка для всех 8 типов без развилки.
type Header struct {
	Type     FrameType
	Flags    Flags
	StreamID uint64 // varint на проводе; 0, если фрейм не привязан к конкретному логическому потоку
}

// SackBlock — блок дополнительного подтверждения с delta-кодированием,
// работает в той же half-open семантике, что и AckFrame.CumAck (см. ниже):
// блок описывает диапазон [start, start+Length), где start вычисляется
// как сумма CumAck и всех Gap+Length предыдущих блоков.
type SackBlock struct {
	Gap    uint64 // Сколько фреймов пропущено между концом предыдущего блока (или CumAck) и началом этого
	Length uint64 // Сколько фреймов подряд подтверждено в этом блоке.
	// ИНВАРИАНТ: Length == 0 запрещена при декодировании — блок нулевой
	// длины не имеет смысла и создаёт неоднозначность с Gap следующего блока.
	// Decoder обязан возвращать ошибку, если встретит Length == 0.
}

// AckFrame — кумулятивный ACK + SACK-блоки, half-open семантика.
//
// CumAck — ЭКСКЛЮЗИВНАЯ верхняя граница: подтверждено всё с frame index
// СТРОГО МЕНЬШЕ CumAck (т.е. диапазон [0, CumAck)). Seq продолжает
// нумероваться с 0.
//
// Следствия выбранной семантики:
//   - CumAck == 0 однозначно и естественно означает "ничего не подтверждено
//     вообще" (zero-value uint64 без нужды в отдельном sentinel/флаге) —
//     именно это нужно для самого первого ACK сразу после установления сессии.
//   - Первый успешно принятый фрейм с Seq == 0 поднимает CumAck до 1.
//   - SackBlock.Gap/Length складываются в той же системе координат: абсолютный
//     старт первого блока = CumAck + Gap, конец блока = старт + Length, старт
//     следующего блока = (конец предыдущего) + его Gap, и так далее.
//   - Decoder, восстанавливающий абсолютные диапазоны из блоков, обязан
//     проверить, что они монотонно возрастают и не пересекаются — это прямое
//     следствие gap-кодирования, но инвариант нужно проверять явно, а не
//     полагаться на корректность отправителя.
type AckFrame struct {
	CumAck uint64
	Blocks []SackBlock
}

func (f *AckFrame) Type() FrameType { return TypeAck }

// DataFrame — чанк данных логического потока.
//
// Seq — frame index (НЕ байтовый offset), назначается на уровне mpConn для
// конкретного StreamID из Header, растёт на 1 на каждый отправленный чанк
// независимо от того, через какой сабфлоу чанк уйдёт физически. Использует
// ту же систему координат, что и AckFrame.CumAck/SackBlock выше (нумерация с 0).
//
// Payload длиной 0 ЗАПРЕЩЕНА при декодировании: FIN передаётся отдельным
// флагом (FlagFin) на непустом или последнем фрейме, а не отдельным пустым
// DATA-фреймом — иначе появляется бессмысленный класс "фреймов без данных",
// который только тратит полосу и требует отдельной обработки в reorder-буфере.
type DataFrame struct {
	Seq     uint64
	Payload []byte

	// PiggybackAck заполнено только если в Header.Flags выставлен
	// FlagAckPiggyback. На проводе идёт ПОСЛЕ Payload (а не до) — потому что
	// AckFrame самодостаточен по длине через свой Blocks-count, тогда как
	// Payload требует знать длину заранее (varint length перед байтами).
	// Если поменять порядок местами, придётся либо хранить длину
	// piggyback-секции явно, либо парсить "от конца" — оба варианта хуже.
	PiggybackAck *AckFrame
}

func (f *DataFrame) Type() FrameType { return TypeData }

type PingFrame struct{}
type PongFrame struct{}
type PathAddFrame struct{}
type PathRemoveFrame struct{}
type CloseFrame struct{}
type PadFrame struct {
	Payload []byte // Мусорный payload для маскировки размера сетевого трафика
}

func (f *PingFrame) Type() FrameType       { return TypePing }
func (f *PongFrame) Type() FrameType       { return TypePong }
func (f *PathAddFrame) Type() FrameType    { return TypePathAdd }
func (f *PathRemoveFrame) Type() FrameType { return TypePathRemove }
func (f *CloseFrame) Type() FrameType      { return TypeClose }
func (f *PadFrame) Type() FrameType        { return TypePad }
