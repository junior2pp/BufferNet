package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/websocket"
)

var (
	dispositivo     string = "ens33"
	longitudCaptura int32  = 1024
	modoPromiscuo   bool   = true
	err             error
	tiempoSalida    time.Duration = 2 * time.Second
	handle          *pcap.Handle
)

func main() {
	fmt.Println("localhost:8000")
	r := http.NewServeMux()
	r.Handle("/", websocket.Handler(Echo))
	http.ListenAndServe(":8000", r)

}

func Echo(ws *websocket.Conn) {
	var err error

	for {
		var reply string

		if err = websocket.Message.Receive(ws, &reply); err != nil {
			fmt.Println("Mensaje estado OK")
			break
		}

		fmt.Println("Mensaje del cliente " + reply)

		fmt.Println(reply)

		//Envio de packageNet
		if err = packageNet(ws); err != nil {
			break
		}

		// err = websocket.Message.Send(ws, reply)
		// err = websocket.Message.Send(ws, reply)
		// fmt.Println(err)
		// if err != nil {
		// 	fmt.Println("Can't send")
		// 	break
		// }

	}
}

type Test struct {
	User    string `json:"user"`
	Mensaje string `json:"mensaje"`
}

func packageNet(ws *websocket.Conn) error {

	// Abrimos la lectura
	handle, err = pcap.OpenLive(dispositivo, longitudCaptura, modoPromiscuo, tiempoSalida)
	if err != nil { //En el caso de existir algun error mostrarlo
		return err
	}
	//Cerrar cuando se termine
	defer handle.Close() //Luego de terminar de usar la función handle esta se cerrara

	//Utiliza handle para procesar todos los paquetes
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		time.Sleep(time.Second * 1)
		fmt.Println(packet)
		data := &Test{
			User:    "luis",
			Mensaje: "hola como estas"}
		websocket.JSON.Send(ws, data)
	}
	return nil
}

func infoPaquete(paquete gopacket.Packet) {

}
