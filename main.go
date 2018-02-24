package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/websocket"
)

const (
	NewLine = "\n"
	Tab     = "\t"
)

var (
	dispositivo     string = "enp3s0"
	longitudCaptura int32  = 1024
	modoPromiscuo   bool   = false
	err             error
	tiempoSalida    time.Duration = 2 * time.Second
	handle          *pcap.Handle
	Packets         []Packet
)

func main() {
	flag.StringVar(&dispositivo, "d", "enp3s0", "Dispositivo que se va a utilizar para escanear.")
	flag.Parse()

	fmt.Println("Dispositivo: ", dispositivo)

	fmt.Println("localhost:8000")
	r := chi.NewRouter()

	// /api/packet
	//api para eviar los packet
	r.Route("/api", func(r chi.Router) {

		r.Route("/packet", func(r chi.Router) {
			r.Handle("/", websocket.Handler(Echo)) // /api/packte/
			r.Get("/{id}", GetPacket)              // /api/packet/12
		})

		r.Get("/css", func(w http.ResponseWriter, r *http.Request) { // /api/css
			http.ServeFile(w, r, "./view/css/bootstrap.min.css")
		})
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

//Echo maneja el web socket para enviar todos los packets
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

//packetNet Escanea todos los packets de la red
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
		SendPacket(packet, ws)
	}
	return nil
}

//SendPacket Seleciona los diferentes packets y los envia por web socket
func SendPacket(packet gopacket.Packet, ws *websocket.Conn) {

	// packet de ethernet
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet) //Tranformamos

		data, _ := json.MarshalIndent(*ethernetPacket, NewLine, Tab)
		//fmt.Println("Protocol Ethernet >>>> ", string(data))
		p := Packet{
			Tipo:   "ethernet",
			Cuerpo: string(data),
		}
		d := fmt.Sprintln(p)
		Packets = append(Packets, p)
		websocket.Message.Send(ws, d[0:100]+"...") //Enviamos por el web socket
	}

	// Packet UDP
	UDPLayer := packet.Layer(layers.LayerTypeUDP)
	if UDPLayer != nil {
		UDPPacket, _ := UDPLayer.(*layers.UDP) //Tranformamos
		p := Packet{
			Tipo:   "UDP",
			Cuerpo: *UDPPacket,
		}
		data, _ := json.MarshalIndent(p, NewLine, Tab)

		d := fmt.Sprintln(string(data))
		Packets = append(Packets, p)
		websocket.Message.Send(ws, d[0:100]+"...") //Enviamos por el web socket
	}

	// Protocol TCP
	TCPLayer := packet.Layer(layers.LayerTypeTCP)
	if TCPLayer != nil {
		TCPPacket, _ := TCPLayer.(*layers.TCP)                  //Tranformamos
		data, _ := json.MarshalIndent(*TCPPacket, NewLine, Tab) //Tranformamos en json
		//fmt.Println("Protocol tcp >>>> ", string(data))
		p := Packet{
			Tipo:   "TCP",
			Cuerpo: string(data),
		}
		d := fmt.Sprintln(p)
		Packets = append(Packets, p)
		websocket.Message.Send(ws, d[0:100]+"...")
	}

	// controla en Protocol ip-v4
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer != nil {
		ipv4Packet, _ := ipv4Layer.(*layers.IPv4)
		data, _ := json.MarshalIndent(*ipv4Packet, NewLine, Tab)
		//fmt.Println("Protocol ipv4 >>>> ", string(data))
		p := Packet{
			Tipo:   "IPv4",
			Cuerpo: string(data),
		}
		Packets = append(Packets, p)
		d := fmt.Sprintln(p)
		websocket.Message.Send(ws, d[0:100]+"...")
	}

}

func GetPacket(w http.ResponseWriter, r *http.Request) {
	if id := chi.URLParam(r, "id"); id != "" {
		i, _ := strconv.Atoi(id)
		p := GetPacketId(i)
		//enviamos los datos al cliente.
		fmt.Fprintln(
			w,
			"id: ", i, NewLine,
			"Packet: ", p.Cuerpo, NewLine,
			"Tipo: ", p.Tipo, NewLine,
		)
		return
	}
	fmt.Fprintln(w, "Packet no existe.")
	return
}

func GetPacketId(id int) Packet {
	return Packets[id]
}
