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
	keyCount               = 0
	steamChapterPointer    = []uint32{0x01BF8B20, 0x3cc}
	steamCheckpointPointer = []uint32{0x01C55EA8, 0x74, 0x0, 0x3c}

	originChapterPointer    = []uint32{0x01C11BE0, 0x3cc}
	originCheckpointPointer = []uint32{0x01C6EFE0, 0x134, 0xBC, 0x0, 0x3c}

	reloadedChapterPointer    = []uint32{0x01C6EFE0, 0x170, 0x1dc, 0x1e8, 0x3c, 0x528, 0x3cc}
	reloadedCheckpointPointer = []uint32{0x01C6EFE0, 0x134, 0xbc, 0x0, 0x3c}

	gogChapterPointer    = []uint32{0x01C6EFE0, 0x1dc, 0x128, 0x1b8, 0x3c, 0x528, 0x3cc}
	gogCheckpointPointer = []uint32{0x01C6EFE0, 0x170, 0xbc, 0x0, 0x3c}

	activeChapterPointer    = steamChapterPointer
	activeCheckpointPointer = steamCheckpointPointer
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

		// reset count with f12
		if event.Struct.VkCode == 123 {
			keyCount = 0
			gui.keyCount.SetText(strconv.Itoa(keyCount))
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
	window.SetInnerSize(350, 210)
	window.SetTitle("Medge Key Counter")
	window.SetResizable(true)
	window.SetHasBorder(true)
	window.SetOnClose(func() {
		close(done)
	})

	keyCountFont, _ := wui.NewFont(wui.FontDesc{
		Name:   "Inter",
		Height: 100,
		Bold:   true,
	})

	keyCountLabel := wui.NewLabel()
	keyCountLabel.SetFont(keyCountFont)
	keyCountLabel.SetBounds(20, 10, 300, 100)
	keyCountLabel.SetText(strconv.Itoa(keyCount))
	window.Add(keyCountLabel)

	buttonFont, _ := wui.NewFont(wui.FontDesc{
		Name:   "Inter",
		Height: 20,
		Bold:   true,
	})

	steamButton := wui.NewButton()
	steamButton.SetFont(buttonFont)
	steamButton.SetBounds(20, 120, 100, 30)
	steamButton.SetText("steam")
	steamButton.SetOnClick(func() {
		activeChapterPointer = steamChapterPointer
		activeCheckpointPointer = steamCheckpointPointer
	})
	window.Add(steamButton)

	originButton := wui.NewButton()
	originButton.SetFont(buttonFont)
	originButton.SetBounds(125, 120, 100, 30)
	originButton.SetText("origin")
	originButton.SetOnClick(func() {
		activeChapterPointer = originChapterPointer
		activeCheckpointPointer = originCheckpointPointer
	})
	window.Add(originButton)

	reloadedButton := wui.NewButton()
	reloadedButton.SetFont(buttonFont)
	reloadedButton.SetBounds(20, 160, 100, 30)
	reloadedButton.SetText("reloaded")
	reloadedButton.SetOnClick(func() {
		activeChapterPointer = reloadedChapterPointer
		activeCheckpointPointer = reloadedCheckpointPointer
		log.Println("version set to reloaded")
	})
	window.Add(reloadedButton)

	gogButton := wui.NewButton()
	gogButton.SetFont(buttonFont)
	gogButton.SetBounds(125, 160, 100, 30)
	gogButton.SetText("gog")
	gogButton.SetOnClick(func() {
		activeChapterPointer = gogChapterPointer
		activeCheckpointPointer = gogCheckpointPointer
		log.Println("version set to gog")
	})
	window.Add(gogButton)

	gui := guiWindow{
		window:   window,
		keyCount: keyCountLabel,
		steam:    steamButton,
		origin:   originButton,
		reloaded: reloadedButton,
		gog:      gogButton,
		done:     done,
	}

	return gui, nil
}

func startMouseListener(dll *user32util.User32DLL, gui guiWindow) (*user32util.LowLevelMouseEventListener, error) {
	listener, err := user32util.NewLowLevelMouseListener(func(event user32util.LowLevelMouseEvent) {
		// ignore mouse move and mouse button up events
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
		chapterAddr, err := lookupAddr(proc, activeChapterPointer[0]+0x400000, activeChapterPointer[1:]...)
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
		checkpointAddr, err := lookupAddr(proc, activeCheckpointPointer[0]+0x400000, activeCheckpointPointer[1:]...)
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

func lookupAddr(proc kiwi.Process, start uint32, offsets ...uint32) (uint32, error) {
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
	steam    *wui.Button
	origin   *wui.Button
	reloaded *wui.Button
	gog      *wui.Button
	done     chan struct{}
}
