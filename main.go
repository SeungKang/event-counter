package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Andoryuuta/kiwi"
	"github.com/gonutz/wui/v2"
	"github.com/stephen-fox/user32util"
)

var (
	keyCount = 0
)

func main() {
	log.SetFlags(0)
	err := mainWithError()
	if err != nil {
		log.Fatalln("error: ", err)
	}
}

func mainWithError() error {
	gui, err := createGUI()
	if err != nil {
		return fmt.Errorf("failed to create GUI - %w", err)
	}

	go scanMedgeLoop(gui)

	dll, err := user32util.LoadUser32DLL()
	if err != nil {
		return fmt.Errorf("failed to load user32 dll - %w", err)
	}

	pressedKeys := make(map[uint32]struct{})
	log.Println("now listening for keyboard and mouse events - press Ctrl+C to stop")
	keyboardListener, err := startKeyboardListener(dll, pressedKeys, gui)
	if err != nil {
		return fmt.Errorf("failed to start keyboard listener - %w", err)
	}
	defer keyboardListener.Release()

	mouseListener, err := startMouseListener(dll, gui)
	if err != nil {
		return fmt.Errorf("failed to start mouse listener - %w", err)
	}
	defer mouseListener.Release()
	gui.window.Show()

	log.Printf("total key count: %d", keyCount)
	return nil
}

func startKeyboardListener(user32 *user32util.User32DLL, pressedKeys map[uint32]struct{}, gui guiWindow) (*user32util.LowLevelKeyboardEventListener, error) {
	fn := func(event user32util.LowLevelKeyboardEvent) {
		if event.KeyboardButtonAction() == user32util.WMKeyDown {
			_, hasIt := pressedKeys[event.Struct.VkCode]
			if !hasIt {
				pressedKeys[event.Struct.VkCode] = struct{}{}
				keyCount++
				gui.keyCount.SetText(strconv.Itoa(keyCount))
				log.Printf("keyboard down event: %d\n", event.Struct.VkCode)
			}
		}

		if event.KeyboardButtonAction() == user32util.WMKeyUp {
			_, hasIt := pressedKeys[event.Struct.VkCode]
			if hasIt {
				delete(pressedKeys, event.Struct.VkCode)
			}
		}
	}

	listener, err := user32util.NewLowLevelKeyboardListener(fn, user32)
	if err != nil {
		return nil, fmt.Errorf("failed to create listener - %s", err.Error())
	}

	return listener, nil
}

func createGUI() (guiWindow, error) {
	done := make(chan struct{})

	windowFont, _ := wui.NewFont(wui.FontDesc{
		Name:   "Inter",
		Height: -11,
	})

	window := wui.NewWindow()
	window.SetFont(windowFont)
	window.SetInnerSize(300, 120)
	window.SetTitle("Medge Key Counter")
	window.SetResizable(true)
	window.SetHasBorder(true)
	window.SetOnClose(func() {
		close(done)
	})

	keyCountFont, _ := wui.NewFont(wui.FontDesc{
		Name:   "Roboto",
		Height: 100,
		Bold:   true,
	})

	keyCountLabel := wui.NewLabel()
	keyCountLabel.SetFont(keyCountFont)
	keyCountLabel.SetBounds(20, 10, 300, 100)
	keyCountLabel.SetText(strconv.Itoa(keyCount))
	window.Add(keyCountLabel)

	gui := guiWindow{
		window:   window,
		keyCount: keyCountLabel,
		done:     done,
	}

	return gui, nil
}

func startMouseListener(dll *user32util.User32DLL, gui guiWindow) (*user32util.LowLevelMouseEventListener, error) {
	listener, err := user32util.NewLowLevelMouseListener(func(event user32util.LowLevelMouseEvent) {
		action := user32util.MouseButtonAction(event.WParam)
		if action == user32util.WMMouseMove ||
			action == user32util.WMLButtonUp ||
			action == user32util.WMRButtonUp {
			return
		}

		keyCount++
		gui.keyCount.SetText(strconv.Itoa(keyCount))
		log.Printf("mouse event: %x", event.WParam)

	}, dll)
	if err != nil {
		return nil, fmt.Errorf("failed to start listner - %s", err)
	}

	return listener, nil
}

func scanMedgeLoop(gui guiWindow) {
	for {
		err := scanMedgeLoopWithError(gui)
		if err != nil {
			log.Printf("failed to open and/or read from medge process - %s", err)
		}
		time.Sleep(5 * time.Second)
	}
}

func scanMedgeLoopWithError(gui guiWindow) error {
	// Find the process from the executable name.
	proc, err := kiwi.GetProcessByFileName("MirrorsEdge.exe")
	if err != nil {
		return errors.New("failed to find process")
	}
	log.Println("TODO: found the Mirrors Edge process")

	var lastCheckpoint string

	for {
		time.Sleep(50 * time.Millisecond)

		var exitStatus uint32
		err = syscall.GetExitCodeProcess(syscall.Handle(proc.Handle), &exitStatus)
		if err != nil {
			return fmt.Errorf("failed get exit code process - %s", err)
		}

		if exitStatus != 259 {
			// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodeprocess
			// 259 STILL_ACTIVE
			return fmt.Errorf("process exited with status: %d", exitStatus)
		}

		// get current chapter
		chapterAddr, err := getAddr(proc, 0x1FF8B20, 0x3CC)
		if err != nil {
			log.Printf("failed to get current chapter address - %s", err)
			continue
		}

		currentChapter, err := findStringAtAddr(proc, chapterAddr)
		if err != nil {
			log.Println(err)
			continue
		}

		if currentChapter == "TdMainMenu" {
			continue
		}

		// get current checkpoint
		checkpointAddr, err := getAddr(proc, 0x2055EA8, 0x74, 0x0, 0x3C)
		if err != nil {
			log.Println(err)
			continue
		}

		currentCheckpoint, err := findStringAtAddr(proc, checkpointAddr)
		if err != nil {
			log.Println(err)
			continue
		}

		if currentCheckpoint == lastCheckpoint {
			continue
		}

		lastCheckpoint = currentCheckpoint

		chapterCheckpoint := strings.ToLower(currentChapter + "_" + currentCheckpoint)

		if chapterCheckpoint == "tutorial_p_start" {
			keyCount = 0
			gui.keyCount.SetText(strconv.Itoa(keyCount))
			continue
		}

		log.Printf("%s", chapterCheckpoint)
	}
}

func getAddr(proc kiwi.Process, start uint32, offsets ...uint32) (uint32, error) {
	stringAddr, err := proc.ReadUint32(uintptr(start))
	if err != nil {
		return 0, fmt.Errorf("error while trying to read from target process at 0x%x - %w", stringAddr, err)
	}

	for _, offset := range offsets {
		stringAddr, err = proc.ReadUint32(uintptr(stringAddr + offset))
		if err != nil {
			return 0, fmt.Errorf("error while trying to read from target process at 0x%x - %w", stringAddr, err)
		}
	}
	return stringAddr, nil
}

func findStringAtAddr(proc kiwi.Process, initialAddr uint32) (string, error) {
	currentAddr := initialAddr
	buf := bytes.NewBuffer(nil)
	maxReads := 69
	term := []byte{0x00, 0x00, 0x00}
	chunkSlice := make([]byte, 4)

	for i := 0; i < maxReads; i++ {

		chunk, err := proc.ReadUint32(uintptr(currentAddr))
		if err != nil {
			return "", fmt.Errorf("failed to read memory at 0x%x - %w", currentAddr, err)
		}

		binary.LittleEndian.PutUint32(chunkSlice, chunk)
		buf.Write(chunkSlice)

		if j := bytes.Index(buf.Bytes(), term); j > -1 {
			chapterName := strings.ReplaceAll(string(buf.Bytes()[0:j]), "\x00", "")

			return chapterName, nil

		}

		currentAddr += 0x4
	}

	return "", nil
}

type guiWindow struct {
	window   *wui.Window
	keyCount *wui.Label
	done     chan struct{}
}
