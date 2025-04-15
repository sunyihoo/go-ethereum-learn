package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/beevik/ntp"
)

func main() {
	Ntp()
}

func Ntp() {
	t, err := ntp.Time("pool.ntp.org")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("NTP time:", t)
}

func BigEnd() {
	var b [8]byte
	rand.Read(b[:])
	fmt.Println(b)
	fmt.Println(binary.BigEndian.Uint64(b[:]))
	fmt.Println(binary.LittleEndian.Uint64(b[:]))
	// [138 72 168 234 250 43 43 144]
	data := []byte{138, 72, 168, 234, 250, 43, 43, 144}
	// 序列   | 内存顺序表示
	// 大端序 | 8A 48 A8 EA FA 2B 2B 90 （高位 → 低位）
	// 小端序 | 90 2B 2B FA EA A8 48 8A （低位 → 高位）

	// 大端序读取
	big := binary.BigEndian.Uint64(data)
	fmt.Printf("BigEndian:      %d (0x%X)\n", big, big)

	// 小端序读取
	little := binary.LittleEndian.Uint64(data)
	fmt.Printf("LittleEndian:      %d (0x%X)\n", little, little)

}
