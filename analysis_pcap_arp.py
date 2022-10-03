import dpkt
import struct
import socket
import binascii

listOfARPRequests = []
reqrep = []

class ARPPacket():
    def __init__(self):
        hardware_type: -1
        protocol_type: -1
        hardware_size = -1
        protocol_size = -1
        opcode = -1
        sender_hardware_addr = -1
        target_hardware_addr = -1
        sender_protocol_addr = -1
        target_protocol_addr = -1

def buildMAC(hexString):
    sub = ""
    list = []
    charCount = 0
    index = 0
    for c in hexString:
        if(charCount == 2):
            charCount = 0
            list.append(sub)
            sub = ""
        sub = sub + c
        charCount = charCount + 1
        index = index + 1
    MACAddress = ":".join(list)
    return MACAddress

def reqHasAddr(MAC):
    for pkt in listOfARPRequests:
        if(pkt.sender_hardware_addr == MAC):
            return True
    return False

def printARPPacket(packet):
    if(not(packet == None)):
        print("Hardware Type: " + str(packet.hardware_type))
        print("Protocol Type: " + str(packet.protocol_type))
        print("Hardware Size: " + str(packet.hardware_size))
        print("Protocol Size: " + str(packet.protocol_size))
        print("Opcode: " + str(packet.opcode))
        print("Sender Hardware Address: " + str(packet.sender_hardware_addr))
        print("Target Hardware Address: " + str(packet.target_hardware_addr))
        print("Sender Protocol Address: " + str(packet.sender_protocol_addr))
        print("Target Protocol Address: " + str(packet.target_protocol_addr))

def analyze_pcap(pcap_file_path):
    try: #ATTEMPT TO OPEN THE PCAP FILE; OTHERWISE, THROW AN EXCEPTION AND EXIT THE PROGRAM
        pcapfile = open(pcap_file_path, 'rb')
        readpcap = dpkt.pcap.Reader(pcapfile) #set up PCAP reader
    except FileNotFoundError:
        print("Invalid file/filepath. Exiting program")
        return

    request = ARPPacket()
    reply = ARPPacket()

    for ts, buf in readpcap:
        EthType = buf[12:14]
        payload = buf[14:42]
        if not (EthType.hex() == "0806"): #checks the type to see if ARP packet
            continue
        else:
            HWAddrType, PAddrType, HWAddrLen, ProtoAddrLen, Opcode, SrcHWAddr, SrcProtocolAddr, DestHWAddr, DestProtocolAddr = struct.unpack("2s2s1s1s2s6s4s6s4s", payload)
            if(int.from_bytes(Opcode, "big") == 1):
                #FILL IN ARP PACKET INFORMATION
                request.hardware_type = int.from_bytes(HWAddrType, "big")
                request.protocol_type = hex(int.from_bytes(PAddrType, "big"))
                request.hardware_size = int.from_bytes(HWAddrLen, "big")
                request.protocol_size = int.from_bytes(ProtoAddrLen, "big")
                request.opcode = int.from_bytes(Opcode, "big")

                #CONVERT HW ADDRESSES INTO MAC ADDRESSES AND FILL IN INFORMATION
                addrStr = str(binascii.hexlify(SrcHWAddr))
                addrStr = addrStr[2:len(addrStr) - 1]
                request.sender_hardware_addr = buildMAC(addrStr)
                #ARPReqSrc = request.sender_hardware_addr

                addrStr = str(binascii.hexlify(DestHWAddr))
                addrStr = addrStr[2:len(addrStr) - 1]
                request.target_hardware_addr = buildMAC(addrStr)

                #CONVERT PROTOCOL ADDRESSES INTO IP ADDRESSES AND FILL IN INFORMATION
                request.sender_protocol_addr = socket.inet_ntoa(SrcProtocolAddr)
                request.target_protocol_addr = socket.inet_ntoa(DestProtocolAddr)

                #APPEND THE REQUEST PACKET TO THE LIST OF REQUEST PACKETS
                listOfARPRequests.append(request)
            elif((int.from_bytes(Opcode, "big") == 2)):
                EthDestMAC = buf[:6]
                EthDestMAC = str(binascii.hexlify(EthDestMAC))
                EthDestMAC = EthDestMAC[2:len(EthDestMAC) - 1]
                EthDestMAC = buildMAC(EthDestMAC)
                #WE WANT TO SKIP GRATUITOUS ARP REPLY PACKETS
                if(EthDestMAC == "ff:ff:ff:ff:ff"):
                    continue
                
                #FILL IN ARP PACKET INFORMATION
                reply.hardware_type = int.from_bytes(HWAddrType, "big")
                reply.protocol_type = hex(int.from_bytes(PAddrType, "big"))
                reply.hardware_size = int.from_bytes(HWAddrLen, "big")
                reply.protocol_size = int.from_bytes(ProtoAddrLen, "big")
                reply.opcode = int.from_bytes(Opcode, "big")

                #CONVERT HW ADDRESSES INTO MAC ADDRESSES AND FILL IN INFORMATION
                addrStr = str(binascii.hexlify(SrcHWAddr))
                addrStr = addrStr[2:len(addrStr) - 1]
                reply.sender_hardware_addr = buildMAC(addrStr)

                addrStr = str(binascii.hexlify(DestHWAddr))
                addrStr = addrStr[2:len(addrStr) - 1]
                reply.target_hardware_addr = buildMAC(addrStr)

                #CONVERT PROTOCOL ADDRESSES INTO IP ADDRESSES AND FILL IN INFORMATION
                reply.sender_protocol_addr = socket.inet_ntoa(SrcProtocolAddr)
                reply.target_protocol_addr = socket.inet_ntoa(DestProtocolAddr)
                reqrep.append(request)
                reqrep.append(reply)
                return reqrep
1

def main():
    input_pcap_file = input("Please enter a valid path to the desired PCAP file for ARP analysis: ")
    answer = analyze_pcap(input_pcap_file)
    #print(requestPkt)
    print("\nARP Request Packet: ")
    printARPPacket(answer[0])
    print("\n")
    print("ARP Reply Packet: ")
    printARPPacket(answer[1])


if __name__ == "__main__":
    main()