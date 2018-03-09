package main

import (
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
	NewLine 	= "\n"
	Tab     	= "\t"
)

var (
	dispositivo     	string = "ens33"
	longitudCaptura 	int32  = 1024
	modoPromiscuo   	bool   = false
	err             	error
	tiempoSalida    	time.Duration = 2 * time.Second
	handle          	*pcap.Handle
	Packets        		= make(map[int]gopacket.Packet)	//Mapa para guardar los packets
	Id              	int
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
		r.Handle("/ws", websocket.Handler(Echo)) // /api/packte/

		r.Route("/packet", func(r chi.Router) {
			r.Get("/{id}", GetPacket)              // /api/packet/12
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
func Echo(ws *websocket.Conn) {
	var err error

	for {
		var msg string

		if err = websocket.Message.Receive(ws, &msg); err != nil {
			fmt.Println("Conexion Cerrada ", err)
			break
		}
		fmt.Println("Mensaje: ", msg)
	

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
	
	Packets[Id] = packet


	var capas = make([]string, 0)
	for _, layer := range packet.Layers() {
		capas = append(capas, fmt.Sprint(layer.LayerType()))
	}

	prefi := Pre{
		Id:   Id,
		Capas: fmt.Sprint(capas),
	}

	websocket.JSON.Send(ws, prefi)	//Enviamos los datos previos
	fmt.Println(prefi)
	Id++
	return
}
var (
	ethLayer layers.Ethernet
	ipLayer  layers.IPv4
	tcpLayer layers.TCP
)

func GetPacket(w http.ResponseWriter, r *http.Request) {
	if id := chi.URLParam(r, "id"); id != "" {
		i, _ := strconv.Atoi(id)

		pa := Packets[i]


		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			&ethLayer,
			&ipLayer,
			&tcpLayer,
		)
		foundLayerTypes := []gopacket.LayerType{}

		err := parser.DecodeLayers(pa.Data(), &foundLayerTypes)
		if err != nil {
			fmt.Println("Problemas al decodificar: ", err)
		}

		for _, layerType := range foundLayerTypes {
			if layerType == layers.LayerTypeEthernet {
				fmt.Fprintln(w, "<br>", "LayerTypeEthernet")
				fmt.Fprintln(w, "<br>", "DstMAC: ", ethLayer.DstMAC)
			}
			if layerType == layers.LayerTypeIPv4 {
				fmt.Fprintln(w, "<br>", "LayerTypeIPv4")
				fmt.Fprintln(w, "<br>", "IPv4: ", ipLayer.SrcIP, "->", ipLayer.DstIP)
			}
			if layerType == layers.LayerTypeTCP {
				fmt.Fprintln(w, "<br>", "LayerTypeTCP")
				fmt.Fprintln(w, "<br>","TCP Port: ", tcpLayer.SrcPort, "->", tcpLayer.DstPort)
				fmt.Fprintln(w, "<br>","TCP SYN:", tcpLayer.SYN, " | ACK:", tcpLayer.ACK)
				fmt.Fprintln(w, "<br>", tcpLayer.Window)
			}
		}

		return
	}
	fmt.Fprintln(w, "Packet no existe.")
	return
}

type Pre struct {
	Id    int
	Capas string
}

type Packet struct {
	Id   	int
	Data 	interface{}
}
