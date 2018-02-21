package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/websocket"
)

var (
	dispositivo     string = "enp3s0"
	longitudCaptura int32  = 1024
	modoPromiscuo   bool   = false
	err             error
	tiempoSalida    time.Duration = 2 * time.Second
	handle          *pcap.Handle
)

func main() {
	fmt.Println("localhost:8000")
	r := chi.NewRouter()

	// /api/packet
	//api para eviar los packet
	r.Route("/api", func(r chi.Router) {
		r.Handle("/packet", websocket.Handler(Echo))
	})

	r.Get("/", Inicio) //Enviar el html and js
	http.ListenAndServe(":8000", r)

}

//Pagina inicial
func Inicio(w http.ResponseWriter, r *http.Request) {

	t, err := template.ParseFiles("./view/index.html")

	if err != nil {
		log.Println("Error del Template. ", err)
	}
	t.Execute(w, nil)

	return
}

func Echo(ws *websocket.Conn) {
	var err error

	for {
		var reply string

		if err = websocket.Message.Receive(ws, &reply); err != nil {
			fmt.Println("Mensaje estado OK ")
			break
		}

		fmt.Println("Mensaje del cliente " + reply)

		fmt.Println(reply)
		websocket.Message.Send(ws, reply)

		//Envio de packageNet
		if err := packageNet(ws); err != nil {
			break
		}
	}
	return
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
		//fmt.Println(packet)
		SendPacket(packet)
		data := fmt.Sprint(packet)
		websocket.Message.Send(ws, data) //enviamos los datos
	}
	return nil
}

//SendPacket Envia los packete selecionado
func SendPacket(packet gopacket.Packet) {

	// packet de ethernet
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet) //Tranformamos

		fmt.Println("packet de ethernet >>>>> ", *ethernetPacket) //Imprimimos
	}

	// Packet UDP
	UDPLayer := packet.Layer(layers.LayerTypeUDP)
	if UDPLayer != nil {
		UDPPacket, _ := UDPLayer.(*layers.UDP)        //Tranformamos
		fmt.Println("packet de UDP ----", *UDPPacket) //Imprimimos
	}

}
