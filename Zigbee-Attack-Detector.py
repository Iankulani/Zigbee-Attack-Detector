# -*- coding: utf-8 -*-
"""
Created on Mon Mar 3 6:10:47 2025

@author: IAN CARTER KULANI

"""

from colorama import Fore
import pyfiglet
import os
font=pyfiglet.figlet_format("Zigbee Attack Detector")
print(Fore.GREEN+font)

import scapy.all as scapy
import time
import pyshark

# Function to detect Zigbee frames
def is_zigbee_packet(packet):
    """Check if the packet is a Zigbee packet."""
    # Example: Check if the packet contains Zigbee IEEE 802.15.4 headers
    if "Dot15d4" in packet:
        return True
    return False

# Function to detect replay attacks (by checking repeated packets)
class ReplayAttackDetector:
    def __init__(self):
        self.packet_hashes = set()

    def detect_replay_attack(self, packet):
        """Detect replay attack by storing packet hashes."""
        packet_hash = hash(packet.summary())  # Use packet summary to create a hash
        if packet_hash in self.packet_hashes:
            return True
        self.packet_hashes.add(packet_hash)
        return False

# Function to analyze packets for suspicious behavior
def analyze_packet(packet, replay_detector):
    """Analyze the captured packet and look for suspicious patterns."""
    if is_zigbee_packet(packet):
        print(f"Zigbee Packet detected: {packet.summary()}")

        # Check for replay attack
        if replay_detector.detect_replay_attack(packet):
            print("[ALERT] Replay attack detected!")
        
        # Add more attack detection logic here (e.g., jamming, spoofing)
        # For example, detecting if the source address is from an unauthorized device:
        if "IEEE802_15_4" in packet:
            src_addr = packet[scapy.Dot15d4].src
            print(f"Source Address: {src_addr}")
            # Simulate an unauthorized device check (this would be based on a known list of devices)
            if src_addr == "INVALID_DEVICE_ADDR":
                print("[ALERT] Unauthorized device detected!")
    else:
        print("Non-Zigbee packet detected.")

# Function to sniff network packets and analyze them
def sniff_packets(interface, duration=30):
    """Sniff Zigbee packets and analyze them for suspicious behavior."""
    replay_detector = ReplayAttackDetector()

    print(f"Starting to sniff Zigbee traffic on {interface} for {duration} seconds...")
    scapy.sniff(iface=interface, timeout=duration, prn=lambda packet: analyze_packet(packet, replay_detector))

def main():
    print("Welcome to the Zigbee Attack Detection Tool (for Educational Use)!")

    # Get the interface name for packet capture (e.g., wlan0, eth0, etc.)
    interface = input("Please enter the network interface (e.g., wlan0):").strip()

    # Get the IP address (just for display purposes, actual sniffing is on the interface)
    ip_address = input("Please enter the IP address to monitor: ").strip()

    # Sniff packets on the network interface for a certain duration
    duration = int(input("Enter duration for packet sniffing (in seconds):").strip())
    sniff_packets(interface, duration)

    print("Packet sniffing complete.")

if __name__ == "__main__":
    main()
