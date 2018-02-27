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
	"github.com/gorilla/websocket"
)

const (
	NewLine = "\n"
	Tab     = "\t"
)

var (
	dispositivo     string = "ens33"
	longitudCaptura int32  = 1024
	modoPromiscuo   bool   = false
	err             error
	tiempoSalida    time.Duration = 2 * time.Second
	handle          *pcap.Handle
	Packets         []Packet
	Id              int
	clientes        = make(map[*websocket.Conn]bool) //Clientes conectados
	broadcast       = make(chan Packet)
	canalPacket     = make(chan gopacket.Packet)
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func main() {
	flag.StringVar(&dispositivo, "d", "enp3s0", "Dispositivo que se va a utilizar para escanear.")
	flag.Parse()

	go packageNet()
	go handlePackets()

	fmt.Println("Dispositivo: ", dispositivo)

	fmt.Println("localhost:8000")
	r := chi.NewRouter()

	// /api/packet
	//api para eviar los packet
	r.Route("/api", func(r chi.Router) {

		r.HandleFunc("/ws", handleConexion)

		r.Route("/packet", func(r chi.Router) {
			//r.HandleFunc("/ws", handleConexion) // ws://localhost:8000/api/packte/ws
			r.Get("/{id}", GetPacket) // /api/packet/12
		})

		//Enviamos los archvios css
		r.Get("/css/{name}", func(w http.ResponseWriter, r *http.Request) { // /api/css
			name := chi.URLParam(r, "name")
			http.ServeFile(w, r, "./view/css/"+name)
		})

		//Enviamos los archivos js
		r.Get("/js/{name}", func(w http.ResponseWriter, r *http.Request) {
			name := chi.URLParam(r, "name")
			http.ServeFile(w, r, "./view/js/"+name)
		})

		//Enviamos los Fonts
		r.Get("/fonts/roboto/{name}", func(w http.ResponseWriter, r *http.Request) {
			name := chi.URLParam(r, "name")
			http.ServeFile(w, r, "./view/fonts/roboto/"+name)
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
func handleConexion(w http.ResponseWriter, r *http.Request) {

	//Actualizar la solicituid GET inicial a un webSocket
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer ws.Close()

	//Registramos al cliente
	clientes[ws] = true

	for {
		messageType, p, err := ws.ReadMessage()
		if err != nil {
			log.Println(err)
			return
		}
		fmt.Println(messageType, string(p))

	}

	/*
		var err error

		for {
			var reply string

			if err = websocket.Message.Receive(ws, &reply); err != nil {
				fmt.Println("Mensaje estado OK ")
				break
			}

			//Envio de packageNet
			if err := packageNet(ws); err != nil {
				break
			}
		}
	*/
	return
}

func handlePackets() {
	for {
		paquete := <-canalPacket

		for cliente := range clientes {
			err := cliente.WriteMessage(1, []byte(fmt.Sprint(paquete)))
			if err != nil {
				log.Printf("Error: %v", err)
				cliente.Close()
				delete(clientes, cliente)
			}
		}
	}
}

//packetNet Escanea todos los packets de la red
func packageNet() {

	// Abrimos la lectura
	handle, err = pcap.OpenLive(dispositivo, longitudCaptura, modoPromiscuo, tiempoSalida)
	if err != nil { //En el caso de existir algun error mostrarlo
		return
	}
	//Cerrar cuando se termine
	defer handle.Close() //Luego de terminar de usar la función handle esta se cerrara

	//Utiliza handle para procesar todos los paquetes
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		canalPacket <- packet //enviamos el Packet por el canal
	}
	return
}

//SendPacket Seleciona los diferentes packets y los envia por web socket
func SendPacket(packet gopacket.Packet, ws *websocket.Conn) {

	// packet de ethernet
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet) //Tranformamos

		data, _ := json.MarshalIndent(*ethernetPacket, NewLine, Tab)

		pa := Packet{
			Id:   Id,
			Data: string(data),
		}
		Id++ //Incrementamos
		Packets = append(Packets, pa)
		fmt.Println(pa.Id)
		websocket.ReadJSON(ws, pa) //Enviamos por el web socket
	}

	// Packet UDP
	UDPLayer := packet.Layer(layers.LayerTypeUDP)
	if UDPLayer != nil {
		UDPPacket, _ := UDPLayer.(*layers.UDP) //Tranformamos
		data, _ := json.MarshalIndent(*UDPPacket, NewLine, Tab)

		pa := Packet{
			Id:   Id,
			Data: string(data),
		}
		Id++
		Packets = append(Packets, pa)

		websocket.ReadJSON(ws, pa) //Enviamos por el web socket
	}

	// Protocol TCP
	TCPLayer := packet.Layer(layers.LayerTypeTCP)
	if TCPLayer != nil {
		TCPPacket, _ := TCPLayer.(*layers.TCP)                  //Tranformamos
		data, _ := json.MarshalIndent(*TCPPacket, NewLine, Tab) //Tranformamos en json
		pa := Packet{
			Id:   Id,
			Data: string(data),
		}
		Id++
		Packets = append(Packets, pa)
		websocket.ReadJSON(ws, pa)
	}

	// controla en Protocol ip-v4
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer != nil {
		ipv4Packet, _ := ipv4Layer.(*layers.IPv4)
		data, _ := json.MarshalIndent(*ipv4Packet, NewLine, Tab)
		pa := Packet{
			Id:   Id,
			Data: string(data),
		}
		Id++
		Packets = append(Packets, pa)
		websocket.ReadJSON(ws, pa)
	}

}

func GetPacket(w http.ResponseWriter, r *http.Request) {
	if id := chi.URLParam(r, "id"); id != "" {
		i, _ := strconv.Atoi(id)
		fmt.Fprintln(w, GetPacketId(i).Data)
		return
	}
	fmt.Fprintln(w, "Packet no existe.")
	return
}

func GetPacketId(id int) Packet {
	return Packets[id]
}

type Packet struct {
	Id   int
	Data interface{}
}
