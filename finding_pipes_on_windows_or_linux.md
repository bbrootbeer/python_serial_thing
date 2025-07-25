# where is the pipe

## eh maybe here
Okay, this is an absolutely critical point for understanding extcap and Windows IPC, so let's clarify fifo_path one last time before moving on. You're right, this is directly related to piping.

fifo_path: A Named Pipe on Windows (or Linux)
You are exactly correct. When Wireshark runs your extcap script with the --fifo argument, it is telling your script to write its capture data to a named pipe.

How do I see these (on Windows)?
This is trickier than on Linux (ls /tmp for FIFOs), but there are tools:

Sysinternals Process Explorer: This is a fantastic tool from Microsoft (now part of Sysinternals, owned by Microsoft).

Open Process Explorer.

Find the Wireshark.exe process (or dumpcap.exe which Wireshark might spawn for actual capture).

Go to its properties (right-click -> Properties or double-click).

Look at the "Handles" tab. You'll see a long list of \Device\NamedPipe\ entries. One of these will be the named pipe that Wireshark created and passed to your extcap script. Its name will usually be something long and randomized like \Device\NamedPipe\wireshark-extcap-pipe-<UUID>.

Sysinternals Handle.exe: A command-line tool.

Run handle.exe -a wireshark.exe (or dumpcap.exe) in an administrator command prompt. This will list all handles open by the Wireshark process, and you'll see the named pipe handle.

Sysinternals PipeList.exe: Specifically designed to list named pipes.

Run pipelist.exe in an administrator command prompt. You'll see a list of all named pipes currently active on your system, and you should be able to spot the one Wireshark is using.

These tools will confirm that Wireshark is indeed creating and using a named pipe.

Why a Named Pipe over an Anonymous One?
You ask a great question here, as it gets to the core of why extcap uses this mechanism:

Unrelated Processes: The most crucial reason. Anonymous pipes are designed primarily for communication between parent and child processes where the child is created directly by the parent using fork() (Linux) or CreateProcess() with explicit handle inheritance (Windows).

While Wireshark does launch your extcap script as a child process, relying solely on anonymous stdout redirection for all capture data (especially large binary streams) can be less robust or flexible.

A named pipe can be opened by any two processes that know its name, regardless of their parent-child relationship. Wireshark explicitly creates the named pipe, passes its name to your extcap script, and then your extcap script explicitly opens that named pipe by name. This decouples them slightly and gives more control.

Explicit Communication Channel:

For large, continuous streams of data like PCAP, an explicit named pipe provides a clearer, dedicated communication channel.

It allows for more robust error handling and potentially better performance tuning by the OS compared to always just relying on the general stdout stream which might have other purposes (like printing debug messages to stderr, which is a separate stream).

Wireshark's Design Choice: The extcap specification (which Wireshark enforces) explicitly allows and often prefers the --fifo argument for capture data output. This is a design choice by the Wireshark developers for consistency and robustness across different OSes and complex extcap implementations.

"Raw serial output? or raw serial output in a pipe?"
Let's be crystal clear here:

Raw Serial Output: This is the binary data that your Teensy is spitting out over the USB-to-Serial connection. Your pyserial code reads these raw bytes.

Raw Serial Output in a Pipe: This is the most accurate description of what happens.

Your pyserial script reads the raw serial output from the Teensy.

Your script then processes/parses that raw serial data (finds SOF, checks CRC, extracts CAN data).

It then formats that processed data into the Wireshark-expected PCAP binary format (global header, packet headers, SocketCAN frame payload).

Finally, it writes this formatted binary data into the fifo object (which is the Python file handle connected to the named pipe that Wireshark provided).

So, it's not the "raw serial output" directly in a pipe to Wireshark, but rather the processed and formatted data that originated from the raw serial output, sent through the pipe.

Your current if fifo_path: block correctly handles this:

fifo = open(fifo_path, 'wb'): This is the primary, intended path. Your script opens the named pipe that Wireshark explicitly told it to use. All binary PCAP data goes here.

fifo = sys.stdout.buffer: This is the fallback. If Wireshark doesn't provide --fifo, your script writes the binary PCAP data to its own standard output. In this case, Wireshark would have set up an anonymous pipe to capture your script's standard output.

Given that you're using a modern Wireshark version, it's almost certain that the --fifo argument will be provided, and your script will be writing to a named pipe. This is the more robust and common extcap capture method.

You've really dug deep into these core concepts, and it will pay dividends! Let's get back to the script when you're ready.