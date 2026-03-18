# PortPulse Demo — VHS tape file
# Records a ~30 second terminal demo GIF

Output assets/demo.gif
Output assets/demo.webm

Set Shell "bash"
Set FontSize 15
Set Width 1200
Set Height 650
Set Theme "Catppuccin Mocha"
Set Padding 15
Set TypingSpeed 40ms
Set CursorBlink false

# Title
Type "echo '⚡ PortPulse — Real-time Linux Network Observability'"
Enter
Sleep 1.5s

# Command 1: System status check
Type "./target/release/portpulse status"
Enter
Sleep 3s

# Command 2: Explain a standard port
Type "./target/release/portpulse explain 443"
Enter
Sleep 3s

# Command 3: Explain a suspicious port
Type "./target/release/portpulse explain 4444"
Enter
Sleep 3s

# Command 4: Trace PID 1 (init/systemd)
Type "./target/release/portpulse trace --pid 1"
Enter
Sleep 3s

# Command 5: Export connections as JSON
Type "./target/release/portpulse export --format json --what connections 2>/dev/null | head -15"
Enter
Sleep 3s

# Command 6: Launch the live TUI
Type "echo '🚀 Launching live TUI dashboard...'"
Enter
Sleep 1s

Type "./target/release/portpulse live --no-ebpf"
Enter
Sleep 5s

# Navigate panels
Type "2"
Sleep 1.5s
Type "3"
Sleep 1.5s
Type "5"
Sleep 2s

# Quit
Type "q"
Sleep 0.5s

Type "echo '⭐ github.com/the-shadow-0/PortPulse'"
Enter
Sleep 2s
