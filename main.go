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
	Packets         []PacketSend
	Id              int
	clientes        = make(map[*websocket.Conn]bool) //Clientes conectados
	broadcast       = make(chan Packet)
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func main() {
	flag.StringVar(&dispositivo, "d", "enp3s0", "Dispositivo que se va a utilizar para escanear.")
	flag.Parse()

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

/*
func handlePackets() {
	for {

		for cliente := range clientes {

		}
	}
}
*/

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

type PacketSend struct {
	Id    int
	Capas []string
	layers.Ethernet
	layers.UDP
	layers.TCP
	layers.IPv4
}

//SendPacket Seleciona los diferentes packets y los envia por web socket
func SendPacket(packet gopacket.Packet, ws *websocket.Conn) {
	p1 := PacketSend{Id: Id}

	// packet de ethernet
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet) //Tranformamos
		p1.Ethernet = *ethernetPacket
		/*
			data, _ := json.MarshalIndent(*ethernetPacket, NewLine, Tab)

			pa := Packet{
				Id:   Id,
				Data: string(data),
			}
			Id++ //Incrementamos
			Packets = append(Packets, pa)
			fmt.Println(pa.Id)
			websocket.Message.Send(ws, fmt.Sprint(pa.Id)) //Enviamos por el web socket
		*/
	}

	// Packet UDP
	UDPLayer := packet.Layer(layers.LayerTypeUDP)
	if UDPLayer != nil {
		UDPPacket, _ := UDPLayer.(*layers.UDP) //Tranformamos

		p1.UDP = *UDPPacket
		/*
			data, _ := json.MarshalIndent(*UDPPacket, NewLine, Tab)

			pa := Packet{
				Id:   Id,
				Data: string(data),
			}
			Id++
			Packets = append(Packets, pa)

			websocket.Message.Send(ws, fmt.Sprint(pa.Id)) //Enviamos por el web socket
		*/

	}

	// Protocol TCP
	TCPLayer := packet.Layer(layers.LayerTypeTCP)
	if TCPLayer != nil {
		TCPPacket, _ := TCPLayer.(*layers.TCP) //Tranformamos
		p1.TCP = *TCPPacket

		/*
			data, _ := json.MarshalIndent(*TCPPacket, NewLine, Tab) //Tranformamos en json
			pa := Packet{
				Id:   Id,
				Data: string(data),
			}
			Id++
			Packets = append(Packets, pa)
			websocket.Message.Send(ws, fmt.Sprint(pa.Id))
		*/
	}

	// controla en Protocol ip-v4
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer != nil {
		ipv4Packet, _ := ipv4Layer.(*layers.IPv4)
		p1.IPv4 = *ipv4Packet
		/*
			data, _ := json.MarshalIndent(*ipv4Packet, NewLine, Tab)
			pa := Packet{
				Id:   Id,
				Data: string(data),
			}
			Id++
			Packets = append(Packets, pa)
			websocket.Message.Send(ws, fmt.Sprint(pa.Id))
		*/
	}

	var capas = make([]string, 0)
	for _, layer := range packet.Layers() {
		capas = append(capas, fmt.Sprint(layer.LayerType()))
	}
	p1.Capas = capas

	fmt.Println(capas)
	Packets = append(Packets, p1)
	prefi := Pre{
		Id:    p1.Id,
		Capas: fmt.Sprint(p1.Capas),
	}
	websocket.JSON.Send(ws, prefi)
	Id++
	return
}

type Pre struct {
	Id    int
	Capas string
}

func GetPacket(w http.ResponseWriter, r *http.Request) {
	if id := chi.URLParam(r, "id"); id != "" {
		i, _ := strconv.Atoi(id)
		d, _ := json.MarshalIndent(GetPacketId(i), NewLine, Tab)
		fmt.Fprint(w, string(d))
		return
	}
	fmt.Fprintln(w, "Packet no existe.")
	return
}

func GetPacketId(id int) PacketSend {
	return Packets[id]
}

type Packet struct {
	Id   int
	Data interface{}
}
