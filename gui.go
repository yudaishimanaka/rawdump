package main

import (
	"log"
	"net"

	"github.com/mattn/go-gtk/gdk"
	"github.com/mattn/go-gtk/glib"
	"github.com/mattn/go-gtk/gtk"
	"runtime"
	"time"
)

func htons(host uint16) uint16 {
	return (host&0xff)<<8 | (host >> 8)
}

func capture(window *gtk.Window, ifaceName string) (err error) {
	runtime.GOMAXPROCS(10)
	glib.ThreadInit(nil)
	gdk.ThreadsInit()
	gdk.ThreadsEnter()
	gtk.Init(nil)
	children := window.GetChild()
	children.Destroy()
	window.SetPosition(gtk.WIN_POS_CENTER)
	title := "PcapGo capture from " + ifaceName
	window.SetTitle(title)
	window.SetIconName("gtk-dialog-info")
	window.Maximize()
	window.Connect("destroy", gtk.MainQuit)

	swin := gtk.NewScrolledWindow(nil, nil)

	store := gtk.NewListStore(glib.G_TYPE_STRING, glib.G_TYPE_STRING, glib.G_TYPE_STRING, glib.G_TYPE_STRING, glib.G_TYPE_STRING, glib.G_TYPE_STRING)
	treeview := gtk.NewTreeView()
	swin.Add(treeview)

	treeview.SetModel(store)
	treeview.AppendColumn(gtk.NewTreeViewColumnWithAttributes("No.", gtk.NewCellRendererText(), "text", 0))
	treeview.AppendColumn(gtk.NewTreeViewColumnWithAttributes("Time", gtk.NewCellRendererText(), "text", 1))
	treeview.AppendColumn(gtk.NewTreeViewColumnWithAttributes("Source", gtk.NewCellRendererText(), "text", 2))
	treeview.AppendColumn(gtk.NewTreeViewColumnWithAttributes("Destination", gtk.NewCellRendererText(), "text", 3))
	treeview.AppendColumn(gtk.NewTreeViewColumnWithAttributes("Protocol", gtk.NewCellRendererText(), "text", 4))
	treeview.AppendColumn(gtk.NewTreeViewColumnWithAttributes("Info", gtk.NewCellRendererText(), "text", 5))

	var iter gtk.TreeIter

	// show window
	window.Add(swin)
	window.ShowAll()

	go func() {
		for {
			gdk.ThreadsEnter()
			adj := swin.GetVAdjustment()
			store.Append(&iter)
			store.Set(&iter,
				0, "0",
				1, "0.12345678",
				2, "10.10.10.10",
				3, "20.20.20.20",
				4, "TCP",
				5, "Application Data",
			)
			adj.SetValue(adj.GetUpper() - adj.GetPageSize())
			gdk.ThreadsLeave()
			time.Sleep(500 * time.Millisecond)
		}
		gtk.MainQuit()
	}()

	gtk.Main()

	return nil
}

func main() {
	// initialize
	gtk.Init(nil)

	// create window
	window := gtk.NewWindow(gtk.WINDOW_TOPLEVEL)
	window.SetPosition(gtk.WIN_POS_CENTER)
	window.SetDefaultSize(400, 400)
	window.SetTitle("PcapGo")
	window.Connect("destroy", gtk.MainQuit)

	// get all network interface
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}

	// create radio buttonbox
	buttons := gtk.NewHBox(false, 1)
	buttonbox := gtk.NewVBox(false, 1)

	// create radiobutton iface range
	var buttonlist []*gtk.RadioButton
	var count int
	var buttonf, buttono *gtk.RadioButton
	for index, iface := range ifaces {
		if index == 0 {
			buttonf = gtk.NewRadioButtonWithLabel(nil, iface.Name)
			buttonbox.Add(buttonf)
			buttonlist = append(buttonlist, buttonf)
		} else {
			buttono = gtk.NewRadioButtonWithLabel(buttonf.GetGroup(), iface.Name)
			buttonbox.Add(buttono)
			buttonlist = append(buttonlist, buttono)
		}
		count++
	}
	buttons.Add(buttonbox)
	buttonlist[0].SetActive(true)

	// create capture start button
	// create interface namei
	var ifaceName string
	runButton := gtk.NewButtonWithLabel("Start Capture")
	runButton.Connect("clicked", func() {
		for _, obj := range buttonlist {
			if obj.GetActive() == true {
				ifaceName = obj.GetLabel()
			}
		}
		capture(window, ifaceName)
		gtk.MainQuit()
	})

	// label
	label := gtk.NewLabel("Select interface")
	label.ModifyFontEasy("Ubuntu 20")

	vbox := gtk.NewVBox(false, 1)
	vbox.SetBorderWidth(20)
	vbox.PackStart(label, false, false, 0)
	vbox.PackStart(buttons, false, false, 0)
	vbox.PackStart(runButton, false, false, 0)
	window.Add(vbox)
	window.ShowAll()
	gtk.Main()
}
