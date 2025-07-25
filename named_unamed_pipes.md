# fifo path explained

## the explanation

Is fifo_path like the "kernel buffer"?
You're conceptually very close, but let's refine it slightly:

Anonymous Pipes (like sys.stdout when redirected): These do rely on kernel buffers. When Wireshark sets up an anonymous pipe, the OS kernel allocates a memory buffer. One process writes to it, the kernel stores it, and the other process reads from it. This buffer is ephemeral and typically tied to the lifespan of the processes or the pipe itself.

Named Pipes (FIFOs - what fifo_path points to): These are a bit different. While they also involve kernel buffers for data transfer, they have an entry in the file system (a "name"). You can see them with ls -l on Linux/macOS (they appear as p for pipe). This allows completely unrelated processes to open and communicate through them, even if one wasn't directly forked by the other. They behave like files but are not stored on disk; data written to them is immediately read by the other end and disappears.

So, fifo_path points to a file-system entry that represents a named pipe. When you open() it in write binary mode, you're interacting with a special file that, under the hood, uses kernel buffering to facilitate data transfer between your script and Wireshark.

This distinction allows Wireshark a lot of flexibility in how it manages captures and integrates external tools. By using named pipes, it can run your script as a separate process and have a clean, robust way to receive the raw capture data.

## another explanation

You're not nitpicking at all! Understanding the extcap arguments and the piping mechanisms is absolutely crucial. It's the core of how Wireshark communicates with external tools. You've identified a key insight about --fifo:

The --fifo Argument and Wireshark's Role
You are absolutely correct:

Python

parser.add_argument("--fifo", help="Named pipe (FIFO) to write captured data to")
This line doesn't create the named pipe. Its sole purpose is to tell Python's argparse library that your script expects an argument named --fifo, and that the value associated with it should be treated as a string (help provides a description for users).

You're 100% right: the creation of the named pipe is totally handled by Wireshark.

When you hit "Start" on your "wowcan" interface in Wireshark:

Wireshark creates a unique named pipe (FIFO) file. It does this using operating system calls (e.g., mkfifo() on Linux/macOS, CreateNamedPipe() on Windows). It chooses a temporary, unique path for this FIFO (e.g., /tmp/wireshark_extcap_xyz123).

Wireshark then executes your Python script as a child process. Crucially, it includes the --fifo argument, passing the path to the newly created FIFO:

Bash

python your_extcap_script.py --capture --extcap-interface wowcan --fifo /tmp/wireshark_extcap_xyz123 --serial-port COM4 --baudrate 115200
Your Python script receives this fifo_path value through args.fifo.

Your script opens this existing named pipe for writing (open(fifo_path, 'wb')).

Wireshark, simultaneously, opens the same named pipe for reading.

As your script writes pcap data to the FIFO, Wireshark reads it on the other end, processes it, and displays it.

This design decouples the capture logic (your Python script) from the display and analysis logic (Wireshark), making it very powerful and extensible.