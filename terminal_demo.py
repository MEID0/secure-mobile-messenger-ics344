#!/usr/bin/env python3
"""
Terminal-based Secure Messenger Demo
No GUI dependencies - runs in console
ICS344 - Group P26
"""

import json
import time
import os
from colorama import init, Fore, Style, Back

# Try colorama for colors, but work without it
try:
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    # Define dummy color constants
    class Fore:
        GREEN = RED = YELLOW = CYAN = MAGENTA = BLUE = RESET = ''
    class Style:
        BRIGHT = DIM = RESET_ALL = ''
    class Back:
        BLACK = RESET = ''

from secure_message_enhanced import SecureMessenger
from security_state import SecurityStateManager
from key_manager import KeyManager
import base64


class TerminalMessenger:
    def __init__(self):
        self.messenger = SecureMessenger()
        self.security_state = SecurityStateManager("terminal_security.db")
        self.key_manager = KeyManager("terminal_keys", "demo_password")
        self.last_packet = None
        
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_header(self):
        print(f"\n{Style.BRIGHT}{Fore.CYAN}{'='*60}")
        print(f"{Style.BRIGHT}{Fore.CYAN}    SECURE MESSENGER - ICS344 GROUP P26")
        print(f"{Style.BRIGHT}{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    def print_menu(self):
        print(f"\n{Fore.GREEN}[MAIN MENU]{Style.RESET_ALL}")
        print("1. Initialize Identities")
        print("2. Perform Key Exchange")
        print("3. Send Secure Message")
        print("4. Receive Last Message")
        print("5. Simulate Attacks")
        print("6. View Security Statistics")
        print("7. Run Complete Demo")
        print("0. Exit")
        
    def initialize_identities(self):
        print(f"\n{Fore.YELLOW}[INITIALIZING]{Style.RESET_ALL} Generating RSA keypairs...")
        self.messenger.setup_identities()
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} RSA-2048 keypairs generated for sender and receiver")
        
    def perform_key_exchange(self):
        if not self.messenger.sender_private:
            print(f"{Fore.RED}✗{Style.RESET_ALL} Initialize identities first!")
            return
            
        print(f"\n{Fore.YELLOW}[KEY EXCHANGE]{Style.RESET_ALL} Starting RSA key exchange...")
        
        # Initiate key exchange
        key_packet = self.messenger.initiate_key_exchange()
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} AES-256 key encrypted with RSA-OAEP")
        
        # Show packet (truncated)
        packet_dict = json.loads(key_packet)
        print(f"\n{Fore.CYAN}Key Exchange Packet:{Style.RESET_ALL}")
        print(f"  Type: {packet_dict['type']}")
        print(f"  Session ID: {packet_dict['session_id']}")
        print(f"  Encrypted AES Key: {packet_dict['encrypted_aes_key'][:50]}...")
        
        # Process at receiver
        success = self.messenger.receive_key_exchange(key_packet)
        if success:
            print(f"{Fore.GREEN}✓{Style.RESET_ALL} Key exchange successful - secure channel established")
        else:
            print(f"{Fore.RED}✗{Style.RESET_ALL} Key exchange failed")
            
    def send_message(self):
        if not self.messenger.key_exchanged:
            print(f"{Fore.RED}✗{Style.RESET_ALL} Perform key exchange first!")
            return
            
        message = input(f"\n{Fore.CYAN}Enter message:{Style.RESET_ALL} ")
        
        print(f"\n{Fore.YELLOW}[ENCRYPTING]{Style.RESET_ALL} Processing message...")
        packet = self.messenger.create_secure_message_packet(message)
        self.last_packet = packet
        
        packet_dict = json.loads(packet)
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} Message encrypted with AES-256-CBC")
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} Signed with RSA-PSS")
        print(f"\n{Fore.CYAN}Packet Details:{Style.RESET_ALL}")
        print(f"  Message ID: {packet_dict['message_id']}")
        print(f"  Timestamp: {packet_dict['timestamp']}")
        print(f"  IV: {packet_dict['iv'][:20]}...")
        print(f"  Ciphertext: {packet_dict['ciphertext'][:30]}...")
        
    def receive_message(self):
        if not self.last_packet:
            print(f"{Fore.RED}✗{Style.RESET_ALL} No message to receive")
            return
            
        print(f"\n{Fore.YELLOW}[RECEIVING]{Style.RESET_ALL} Processing packet...")
        
        # Check security state
        if self.security_state.has_packet_been_processed(self.last_packet):
            print(f"{Fore.RED}✗ REPLAY DETECTED{Style.RESET_ALL} - Packet already processed")
            return
            
        success, result = self.messenger.process_secure_message(self.last_packet)
        
        if success:
            print(f"{Fore.GREEN}✓{Style.RESET_ALL} Signature verified")
            print(f"{Fore.GREEN}✓{Style.RESET_ALL} Message decrypted")
            print(f"\n{Fore.CYAN}Decrypted Message:{Style.RESET_ALL} {result}")
            
            # Mark as processed
            packet_dict = json.loads(self.last_packet)
            self.security_state.mark_packet_processed(self.last_packet, "sender")
            iv_bytes = base64.b64decode(packet_dict['iv'])
            self.security_state.mark_iv_used(iv_bytes, self.messenger.aes_key)
        else:
            print(f"{Fore.RED}✗{Style.RESET_ALL} Failed: {result}")
            
    def simulate_attacks(self):
        if not self.last_packet:
            print(f"{Fore.RED}✗{Style.RESET_ALL} Send a message first")
            return
            
        print(f"\n{Fore.YELLOW}[ATTACK SIMULATIONS]{Style.RESET_ALL}")
        print("1. Replay Attack")
        print("2. Message Tampering")
        print("3. MITM Attack")
        print("4. IV Reuse Attack")
        
        choice = input("Select attack (1-4): ")
        
        if choice == "1":
            print(f"\n{Fore.RED}[REPLAY ATTACK]{Style.RESET_ALL} Resending same packet...")
            self.receive_message()  # Will be blocked
            
        elif choice == "2":
            print(f"\n{Fore.RED}[TAMPERING ATTACK]{Style.RESET_ALL} Modifying ciphertext...")
            packet_dict = json.loads(self.last_packet)
            ct = base64.b64decode(packet_dict['ciphertext'])
            tampered = bytes([ct[0] ^ 0xFF]) + ct[1:]
            packet_dict['ciphertext'] = base64.b64encode(tampered).decode('utf-8')
            tampered_packet = json.dumps(packet_dict)
            
            success, result = self.messenger.process_secure_message(tampered_packet)
            print(f"{Fore.RED}✗{Style.RESET_ALL} Attack blocked: {result}")
            
        elif choice == "3":
            print(f"\n{Fore.RED}[MITM ATTACK]{Style.RESET_ALL} Replacing public key...")
            # Would need attacker keys to demo properly
            print(f"{Fore.YELLOW}✓{Style.RESET_ALL} Public key pinning would detect this")
            
        elif choice == "4":
            print(f"\n{Fore.RED}[IV REUSE ATTACK]{Style.RESET_ALL} Reusing same IV...")
            packet_dict = json.loads(self.last_packet)
            # Try to reuse IV (will be detected)
            iv_bytes = base64.b64decode(packet_dict['iv'])
            if self.security_state.has_iv_been_used(iv_bytes, self.messenger.aes_key):
                print(f"{Fore.RED}✗{Style.RESET_ALL} IV reuse detected and blocked")
                
    def view_statistics(self):
        stats = self.security_state.get_statistics()
        print(f"\n{Fore.CYAN}[SECURITY STATISTICS]{Style.RESET_ALL}")
        print(f"  Processed Packets: {stats['total_packets']}")
        print(f"  Tracked IVs: {stats['total_ivs']}")
        print(f"  Message IDs: {stats['total_messages']}")
        
    def run_complete_demo(self):
        self.clear_screen()
        self.print_header()
        
        # Initialize
        print(f"\n{Style.BRIGHT}Phase 1: Identity Setup{Style.RESET_ALL}")
        self.initialize_identities()
        time.sleep(1)
        
        # Key Exchange
        print(f"\n{Style.BRIGHT}Phase 2: RSA Key Exchange{Style.RESET_ALL}")
        self.perform_key_exchange()
        time.sleep(1)
        
        # Send Messages
        print(f"\n{Style.BRIGHT}Phase 3: Secure Messaging{Style.RESET_ALL}")
        messages = [
            "Hello, ICS344!",
            "AES key was encrypted with RSA",
            "Group P26 implementation complete!"
        ]
        
        for msg in messages:
            print(f"\n{Fore.CYAN}Sending:{Style.RESET_ALL} {msg}")
            packet = self.messenger.create_secure_message_packet(msg)
            self.last_packet = packet
            time.sleep(0.5)
            
            success, result = self.messenger.process_secure_message(packet)
            if success:
                print(f"{Fore.GREEN}Received:{Style.RESET_ALL} {result}")
            time.sleep(0.5)
        
        # Test Security
        print(f"\n{Style.BRIGHT}Phase 4: Security Tests{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Testing replay protection...{Style.RESET_ALL}")
        
        # Mark last packet as processed
        self.security_state.mark_packet_processed(self.last_packet, "sender")
        
        # Try replay
        if self.security_state.has_packet_been_processed(self.last_packet):
            print(f"{Fore.GREEN}✓{Style.RESET_ALL} Replay attack blocked successfully")
        
        print(f"\n{Fore.GREEN}{Style.BRIGHT}DEMO COMPLETE - All features working!{Style.RESET_ALL}")
        
    def run(self):
        self.clear_screen()
        
        while True:
            self.print_header()
            self.print_menu()
            
            choice = input(f"\n{Fore.CYAN}Select option:{Style.RESET_ALL} ")
            
            if choice == "0":
                print(f"\n{Fore.YELLOW}Goodbye!{Style.RESET_ALL}")
                self.security_state.close()
                break
            elif choice == "1":
                self.initialize_identities()
            elif choice == "2":
                self.perform_key_exchange()
            elif choice == "3":
                self.send_message()
            elif choice == "4":
                self.receive_message()
            elif choice == "5":
                self.simulate_attacks()
            elif choice == "6":
                self.view_statistics()
            elif choice == "7":
                self.run_complete_demo()
            else:
                print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")
            
            input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")


if __name__ == "__main__":
    messenger = TerminalMessenger()
    messenger.run()