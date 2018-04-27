package main

import (
    "net"
    "log"

    "github.com/mattn/go-gtk/glib"
    "github.com/mattn/go-gtk/gtk"
)

func capture(window *gtk.Window, ifaceName string) {
    children := window.GetChild()
    children.Destroy()
    window.SetPosition(gtk.WIN_POS_CENTER)
    title := "PcapGo capture from "+ifaceName
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
    store.Append(&iter)
    store.Set(&iter,
        0, "0",
        1, "0.12345678",
        2, "10.10.10.10",
        3, "20.20.20.20",
        4, "TCP",
        5, "Application Data",
    )
    store.Append(&iter)
    store.Set(&iter,
        0, "1",
        1, "0.23456789",
        2, "11.11.11.11",
        3, "22.22.22.22",
        4, "UDP",
        5, "51065 →  51065 Len=132",
    )
    store.Append(&iter)
    store.Set(&iter,
        0, "2",
        1, "0.34567891",
        2, "12.12.12.12",
        3, "23.23.23.23",
        4, "ARP",
        5, "Who has 23.23.23.23? Tell 12.12.12.12",
    )
    window.Add(swin)
    window.ShowAll()
    gtk.Main()
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
    runButton := gtk.NewButtonWithLabel("Start")
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

