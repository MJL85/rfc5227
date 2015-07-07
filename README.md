# rfc5227
RFC 5227 Exploit

RFC 5227 introduces a DoS vector for any host that honors the rules it defines, specifically section 2.1.1.  This appears to apply to Windows Vista and later.
  
&nbsp;
  
When the host connects a new NIC to the network with TCP/IP it either attempts to use a statically configured IP address or requests one from an available DHCP server.
  
&nbsp;
  
In either case, once the host has an IP address it wants to use it broadcasts an *ARP probe*.  The purpose of the probe is to determine if the IP address is free to use or if it has already been claimed on the local network segment.
  
&nbsp;
  
The ARP probe is a layer 2 broadcast with following criteria:  

* The ARP source MAC is the MAC of the interface
* The ARP source IP is 0.0.0.0
* The ARP destination MAC is 00:00:00:00:00:00
* The ARP destination IP is the IP address the host NIC is attempting to use
  
&nbsp;
  
When an ARP probe is broadcast all other hosts on that network become aware that the sender intends to use this IP address.  There is then a short time period where the sender will wait.
  
&nbsp;
  
From all other host’s perspectives the IP address defined in the ARP probe has effectively been claimed by the sender, although the sender has not yet decided for itself.  During this time the sender is vulnerable to attack.
  
&nbsp;
  
If all  other hosts interpret this ARP probe as the sender effectively having this IP address, should the sender receive an ARP probe from another host claiming the same IP then the original sender would consider this other host to be using it and an IP conflict to exist.
  
&nbsp;
  
The RFC defines how the host should handle this in section 2.1.1: (https://tools.ietf.org/html/rfc5227 ):  
> If during this period, from the beginning of the probing process
> until ANNOUNCE_WAIT seconds after the last probe packet is sent, the
> host receives any ARP packet (Request *or* Reply) on the interface
> where the probe is being performed, where the packet's 'sender IP
> address' is the address being probed for, then the host MUST treat
> this address as being in use by some other host, and should indicate
> to the configuring agent (human operator, DHCP server, etc.) that the
> proposed address is not acceptable.
  
&nbsp;
  
In the case where the host is using DHCP to obtain an address, the host will proceed to request another IP from the DHCP server should it encounter this issue.
  
&nbsp;
  
In the case where the host is using a statically defined address, it will need to revert to a 169.254.x.x/16 link local address.
  
&nbsp;
  
In each of these cases an ARP probe is also broadcast for the new address.
  
&nbsp;
  
**Some malicious host need only send an ARP to a vulnerable host at the correct time to effectively deny network service.**
  
&nbsp;
  
For a malicious host to attempt to hide from a network administrator it could implement the following as part of the malicious ARP:  

* Set the source MAC address to anything other than itself.  
It might be best to set the source MAC as the destination MAC so that a switch administrator would have a difficult time finding which port it is coming from.
* Implement a probability mechanism where malicious ARPs are not sent for every instance.
* Send the malicious ARP probe to the target host as an L2 unicast rather than a broadcast.
* Deny the use of a link local address through the same ARP mechanism so that it is less obvious that there was an address conflict.
  
&nbsp;
  
As a proof of concept I developed an application which does the above.  It has two modes of operation, one which sends attacks whenever an ARP probe is detected on the network, and one which sends one attack ARP with the specified criteria.
  
&nbsp;
  
I tested this on Windows 7 and Windows 2008 R2 – both were vulnerable.  My iPhone 5s with iOS 7.1.2 was no affected.
  
&nbsp;
  
As a recommended solution for system administrators who don’t want to pull their hair out trying to find something like this you can edit a registry key to disable the IP address conflict detection feature.  
http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=1028373
  
&nbsp;
  
Cisco IOS with the IPDT feature enabled could cause similar IP DoS issues.  Cisco has it documented on [their website](http://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/8021x/116529-problemsolution-product-00.html)
  
&nbsp;
  
**Screenshots**  

* [Command line showing a listening attack.](http://i.imgur.com/7Ux5pY9.jpg)  
The program listens for all ARP probes and automatically DoS's the host sending them.  
The program receives an ARP probe from `00:0c:29:de:45:e8` indicating the host is turning up a NIC to use IP 192.168.100.23.  
The program sends a unicast ARP probe back to `00:0c:29:de:45:e8` saying that it is doing the same thing.  
  
&nbsp;
  
* [Windows Server 2008 R2 (the target from above).](http://i.imgur.com/TK8Inbx.jpg)  
Shows the server was configured with a static IP address of 192.168.100.23 and detected a duplicate IP on the network.  
As a result it assigned itself 169.254.171.12.
  
&nbsp;
  
* [Windows Server 2008 R2 (the target from above again).](http://i.imgur.com/EVN5QVq.jpg)  
The program continued to deny the server IP addresses, even denying 196.254.x.x/16 addresses, and it eventually removed everything except for the gateway from the interface.
  
&nbsp;
  
* [Packet capture on host during attack.](http://i.imgur.com/63eD3sE.jpg)  
Wireshark running on the target host showing ARP activity.
  
&nbsp;
  
**Source code**  
This code requires libpcap, but that should be it.  I tested it on Linux but it should run on any unix-like machine.  
  
Available here: https://github.com/MJL85/rfc5227/blob/master/rfc5227.c
  
*This code is intended for educational purposes only.*
