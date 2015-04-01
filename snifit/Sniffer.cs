using System;
using System.Collections.Generic;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.IpV4;

namespace snifit
{
	static class Sniffer
	{
		public static void Start()
		{
			// Retrieve the device list from the local machine
			IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;

			if (allDevices.Count == 0)
			{
				Console.WriteLine("No interfaces found! Make sure WinPcap is installed.");
				return;
			}

			// Print the list
			for (int i = 0; i != allDevices.Count; ++i)
			{
				LivePacketDevice device = allDevices[i];
//				Console.Write((i + 1) + ". " + device.Name);
				Console.Write((i + 1) + ". ");
				if (device.Description != null)
					Console.WriteLine(" (" + device.Description + ")");
				else
					Console.WriteLine(" (No description available)");
			}

			int deviceIndex;
			do
			{
				Console.WriteLine("Enter the interface number (1-" + allDevices.Count + "):");
				string deviceIndexString = Console.ReadLine();
				if (!int.TryParse(deviceIndexString, out deviceIndex) ||
					deviceIndex < 1 || deviceIndex > allDevices.Count)
				{
					deviceIndex = 0;
				}
			} while (deviceIndex == 0);

			// Take the selected adapter
			PacketDevice selectedDevice = allDevices[deviceIndex - 1];

			// Open the device
			using (PacketCommunicator communicator =
				selectedDevice.Open(65536,                                  // portion of the packet to capture
				// 65536 guarantees that the whole packet will be captured on all the link layers
									PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
									1000))                                  // read timeout
			{
				// Check the link layer. We support only Ethernet for simplicity.
				if (communicator.DataLink.Kind != DataLinkKind.Ethernet)
				{
					Console.WriteLine("This program works only on Ethernet networks.");
					return;
				}

//				 Compile the filter
				using (BerkeleyPacketFilter filter = communicator.CreateFilter("ip and udp"))
				{
//					 Set the filter
					communicator.SetFilter(filter);
				}

				Console.WriteLine("Listening on " + selectedDevice.Description + "...");
				
				// start the capture
				try
				{
					communicator.ReceivePackets(0, PacketHandler);
				}
				catch (Exception e)
				{
					Console.WriteLine(e.Message);
				}
			}
		}

		// Callback function invoked by libpcap for every incoming packet
		private static void PacketHandler(Packet packet)
		{
			switch (packet.Ethernet.IpV4.Protocol)
			{
				case IpV4Protocol.Udp:
					Console.Write(packet.Timestamp.ToString("hh:mm:ss dd-MM-yyyy "));
					printUDPInfo(packet.Ethernet.IpV4);
					break;
				case IpV4Protocol.Tcp:
					Console.Write(packet.Timestamp.ToString("hh:mm:ss dd-MM-yyyy "));
					printTCPInfo(packet.Ethernet.IpV4);
					break;
				default:
					return;
			}
		}

		private static void printUDPInfo(IpV4Datagram IPPacket)
		{
			Console.Write("UDP ");
			Console.Write(IPPacket.Source + ":" + IPPacket.Udp.SourcePort + " -> ");
			Console.Write(IPPacket.Destination + ":" + IPPacket.Udp.DestinationPort + " ");
			Console.WriteLine(IPPacket.Udp.Length + " ");
		}

		private static void printTCPInfo(IpV4Datagram IPPacket)
		{
			Console.Write("TCP ");
			Console.Write(IPPacket.Source + ":" + IPPacket.Tcp.SourcePort + " -> ");
			Console.Write(IPPacket.Destination + ":" + IPPacket.Tcp.DestinationPort + " ");
			Console.WriteLine(IPPacket.Tcp.Length + " ");
		}

	}
}
