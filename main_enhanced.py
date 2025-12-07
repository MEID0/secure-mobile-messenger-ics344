"""
Enhanced Secure Messenger with Complete Security Features
ICS344 - Group P26
Integrates: RSA key exchange, persistent security state, timestamp protection, key management
"""

import json
import base64
import time
import uuid
import os

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.scrollview import ScrollView
from kivy.core.window import Window
from kivy.graphics import Color, Rectangle
from kivy.uix.popup import Popup

# Import all security modules
from aes_cbc import generate_aes_key, encrypt_aes_cbc_with_iv, decrypt_aes_cbc, IV_SIZE
from rsa_sign import (
    generate_rsa_keypair,
    sign_message,
    verify_signature,
    export_public_key_pem,
    load_public_key_pem
)
from rsa_key_exchange import (
    encrypt_aes_key,
    decrypt_aes_key,
    create_key_exchange_packet,
    process_key_exchange_packet
)
from security_state import SecurityStateManager
from key_manager import KeyManager
from secure_message_enhanced import SecureMessenger


class EnhancedSecureMessengerApp(App):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
        # Initialize security components
        self.messenger = SecureMessenger()
        self.security_state = SecurityStateManager("messenger_security.db")
        self.key_manager = KeyManager("messenger_keys", "demo_password")
        
        # Session state
        self.key_exchange_completed = False
        self.session_aes_key = None
        self.session_id = str(uuid.uuid4())
        
        # Attack simulation keys
        self.attacker_priv = None
        self.attacker_pub = None
        
        # UI tracking
        self.last_sent_packet = None
        self.last_honest_packet = None
        self.last_honest_plaintext = None
        
        # UI widgets
        self.recv_text = None
        self.packet_text = None
        self.log_text = None
        self.input_text = None
        self.status_label = None
        
    def build(self):
        self.title = "Enhanced Secure Messenger - ICS344 Group P26"
        
        # Set window size for mobile-like appearance
        Window.size = (450, 800)
        
        # Root layout
        root = BoxLayout(orientation="vertical", padding=8, spacing=5)
        root.bind(size=self._update_bg, pos=self._update_bg)
        
        with root.canvas.before:
            Color(0.95, 0.95, 0.95, 1)
            self.rect = Rectangle(size=root.size, pos=root.pos)
        
        # Status bar
        status_box = BoxLayout(size_hint=(1, 0.08), spacing=5)
        self.status_label = Label(
            text="[b]Status:[/b] Initializing...",
            markup=True,
            size_hint=(0.7, 1),
            color=(0.2, 0.2, 0.2, 1)
        )
        key_status = Label(
            text=f"[b]Session:[/b] {self.session_id[:8]}...",
            markup=True,
            size_hint=(0.3, 1),
            color=(0.2, 0.2, 0.2, 1)
        )
        status_box.add_widget(self.status_label)
        status_box.add_widget(key_status)
        root.add_widget(status_box)
        
        # Tab-like headers
        tabs = BoxLayout(size_hint=(1, 0.06), spacing=2)
        
        recv_header = Label(
            text="[b]📱 Receiver View[/b]",
            markup=True,
            color=(0, 0.5, 0, 1)
        )
        packet_header = Label(
            text="[b]🌐 Network Traffic[/b]",
            markup=True,
            color=(0, 0, 0.7, 1)
        )
        tabs.add_widget(recv_header)
        tabs.add_widget(packet_header)
        root.add_widget(tabs)
        
        # Message displays (side by side)
        displays = BoxLayout(orientation="horizontal", size_hint=(1, 0.35), spacing=5)
        
        # Receiver view
        recv_scroll = ScrollView()
        self.recv_text = TextInput(
            text="[Receiver View - Decrypted Messages]\n",
            multiline=True,
            readonly=True,
            size_hint=(1, None),
            background_color=(0.98, 1, 0.98, 1)
        )
        self.recv_text.bind(minimum_height=self.recv_text.setter('height'))
        recv_scroll.add_widget(self.recv_text)
        
        # Network view
        packet_scroll = ScrollView()
        self.packet_text = TextInput(
            text="[Network Traffic - Encrypted Packets]\n",
            multiline=True,
            readonly=True,
            size_hint=(1, None),
            background_color=(0.98, 0.98, 1, 1),
            font_size='11sp'
        )
        self.packet_text.bind(minimum_height=self.packet_text.setter('height'))
        packet_scroll.add_widget(self.packet_text)
        
        displays.add_widget(recv_scroll)
        displays.add_widget(packet_scroll)
        root.add_widget(displays)
        
        # Security log
        log_header = Label(
            text="[b]🔒 Security Log[/b]",
            markup=True,
            size_hint=(1, 0.05),
            color=(0.5, 0, 0, 1)
        )
        root.add_widget(log_header)
        
        log_scroll = ScrollView(size_hint=(1, 0.2))
        self.log_text = TextInput(
            text="[Security Events]\n",
            multiline=True,
            readonly=True,
            size_hint=(1, None),
            background_color=(1, 0.98, 0.98, 1),
            foreground_color=(0.5, 0, 0, 1)
        )
        self.log_text.bind(minimum_height=self.log_text.setter('height'))
        log_scroll.add_widget(self.log_text)
        root.add_widget(log_scroll)
        
        # Message input
        input_label = Label(
            text="[b]Compose Message:[/b]",
            markup=True,
            size_hint=(1, 0.04),
            color=(0.2, 0.2, 0.2, 1)
        )
        root.add_widget(input_label)
        
        self.input_text = TextInput(
            text="Hello, this is a secure message!",
            multiline=False,
            size_hint=(1, 0.06),
            background_color=(1, 1, 0.95, 1)
        )
        root.add_widget(self.input_text)
        
        # Control buttons
        controls = BoxLayout(size_hint=(1, 0.08), spacing=5)
        
        # Key exchange button
        key_exchange_btn = Button(
            text="🔑 Key Exchange",
            background_color=(0, 0.6, 0.9, 1),
            bold=True
        )
        key_exchange_btn.bind(on_press=self.perform_key_exchange)
        
        send_btn = Button(
            text="📤 Send",
            background_color=(0, 0.7, 0, 1),
            bold=True
        )
        send_btn.bind(on_press=self.send_message)
        
        recv_btn = Button(
            text="📥 Receive",
            background_color=(0, 0.5, 0.8, 1),
            bold=True
        )
        recv_btn.bind(on_press=self.receive_message)
        
        controls.add_widget(key_exchange_btn)
        controls.add_widget(send_btn)
        controls.add_widget(recv_btn)
        root.add_widget(controls)
        
        # Attack simulation panel
        attack_label = Label(
            text="[b]⚡ Attack Simulations:[/b]",
            markup=True,
            size_hint=(1, 0.04),
            color=(0.7, 0, 0, 1)
        )
        root.add_widget(attack_label)
        
        attacks = BoxLayout(size_hint=(1, 0.08), spacing=3)
        
        attack_buttons = [
            ("🔄 Replay", self.simulate_replay_attack, (0.8, 0.4, 0, 1)),
            ("✏️ Tamper", self.simulate_tampering_attack, (0.7, 0, 0.3, 1)),
            ("👤 MITM", self.simulate_mitm_attack, (0.6, 0, 0.6, 1)),
            ("♻️ IV Reuse", self.simulate_iv_reuse_attack, (0, 0.6, 0.6, 1))
        ]
        
        for text, handler, color in attack_buttons:
            btn = Button(text=text, background_color=color, bold=True)
            btn.bind(on_press=handler)
            attacks.add_widget(btn)
        
        root.add_widget(attacks)
        
        # Initialize crypto and show status
        self.initialize_crypto()
        
        return root
    
    def _update_bg(self, instance, value):
        self.rect.pos = instance.pos
        self.rect.size = instance.size
    
    def initialize_crypto(self):
        """Initialize cryptographic components"""
        # Setup identities
        self.messenger.setup_identities()
        
        # Generate attacker keys for demos
        self.attacker_priv, self.attacker_pub = generate_rsa_keypair(2048)
        
        # Check for existing keys in key manager
        if not self.key_manager.get_rsa_keypair("my_identity"):
            # Store the messenger's sender keys
            sender_priv_pem = self.messenger.sender_private.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            sender_pub_pem = export_public_key_pem(self.messenger.sender_public)
            self.key_manager.store_key_pair("my_identity", sender_priv_pem, sender_pub_pem)
            self.log("[INFO] Generated and stored new identity keypair", "blue")
        
        # Clean up old security records
        self.security_state.cleanup_old_records(days=7)
        
        self.status_label.text = "[b]Status:[/b] Ready (Key Exchange Required)"
        self.log("[INIT] System initialized. Perform key exchange before messaging.", "green")
    
    def perform_key_exchange(self, instance):
        """Perform RSA key exchange"""
        try:
            # Initiate key exchange
            key_exchange_packet = self.messenger.initiate_key_exchange()
            
            # Display in network view
            self.packet_text.text += f"\n[KEY EXCHANGE PACKET]\n{key_exchange_packet}\n"
            
            # Simulate receiver processing
            success = self.messenger.receive_key_exchange(key_exchange_packet)
            
            if success:
                self.key_exchange_completed = True
                self.session_aes_key = self.messenger.aes_key
                self.status_label.text = "[b]Status:[/b] ✓ Secure Channel Established"
                self.log("[KEY EXCHANGE] ✓ AES-256 session key successfully exchanged via RSA-OAEP", "green")
                
                # Store session key
                self.key_manager.store_aes_key(f"session_{self.session_id}", self.session_aes_key)
            else:
                self.log("[KEY EXCHANGE] ✗ Failed to establish secure channel", "red")
                
        except Exception as e:
            self.log(f"[ERROR] Key exchange failed: {e}", "red")
    
    def send_message(self, instance):
        """Send encrypted message with all security features"""
        if not self.key_exchange_completed:
            self.log("[WARNING] Perform key exchange before sending messages!", "orange")
            self.show_popup("Security Warning", "Key exchange required before messaging")
            return
        
        plaintext = self.input_text.text.strip()
        if not plaintext:
            return
        
        try:
            # Create secure packet with timestamp
            packet_json = self.messenger.create_secure_message_packet(plaintext)
            
            # Store for attack simulations
            self.last_sent_packet = packet_json
            self.last_honest_packet = packet_json
            self.last_honest_plaintext = plaintext
            
            # Display in network view
            self.packet_text.text += f"\n[SENT PACKET]\n{packet_json}\n"
            
            # Log send event
            self.log(f"[SENT] Message encrypted and signed (len: {len(packet_json)} bytes)", "green")
            
        except Exception as e:
            self.log(f"[ERROR] Failed to send: {e}", "red")
    
    def receive_message(self, instance):
        """Process received message with full security checks"""
        if not self.last_sent_packet:
            self.log("[INFO] No packet to receive", "blue")
            return
        
        self.process_packet_with_security(self.last_sent_packet)
    
    def process_packet_with_security(self, packet_json: str):
        """Process packet with all security checks"""
        try:
            packet = json.loads(packet_json)
            
            # Check packet type
            if packet.get("type") == "key_exchange":
                self.log("[INFO] Key exchange packet - already processed", "blue")
                return
            
            # Check persistent replay protection
            if self.security_state.has_packet_been_processed(packet_json):
                self.log("[REPLAY DETECTED] Packet was already processed (persistent check)", "red")
                return
            
            # Check timestamp if present
            if "timestamp" in packet and "message_id" in packet:
                is_valid, reason = self.security_state.check_timestamp_validity(
                    packet["message_id"],
                    packet["timestamp"],
                    window_seconds=300
                )
                if not is_valid:
                    self.log(f"[TIMESTAMP INVALID] {reason}", "red")
                    return
            
            # Check IV reuse (persistent)
            iv_bytes = base64.b64decode(packet["iv"])
            if self.security_state.has_iv_been_used(iv_bytes, self.session_aes_key):
                self.log("[IV REUSE DETECTED] IV was already used (persistent check)", "red")
                return
            
            # Process message
            success, result = self.messenger.process_secure_message(packet_json)
            
            if success:
                # Mark as processed
                self.security_state.mark_packet_processed(packet_json, packet.get("sender_public_key", ""))
                self.security_state.mark_iv_used(iv_bytes, self.session_aes_key)
                
                # Display decrypted message
                self.recv_text.text += f"\n✓ {result}\n"
                self.log("[RECEIVED] Message verified and decrypted successfully", "green")
            else:
                self.log(f"[SECURITY ERROR] {result}", "red")
                
        except Exception as e:
            self.log(f"[ERROR] Failed to process packet: {e}", "red")
    
    def simulate_replay_attack(self, instance):
        """Simulate replay attack"""
        if not self.last_honest_packet:
            self.log("[INFO] Send a message first", "blue")
            return
        
        self.log("\n[ATTACK] Attempting REPLAY attack...", "orange")
        self.packet_text.text += f"\n[REPLAY ATTACK - Resending previous packet]\n"
        self.process_packet_with_security(self.last_honest_packet)
    
    def simulate_tampering_attack(self, instance):
        """Simulate message tampering"""
        if not self.last_honest_packet:
            self.log("[INFO] Send a message first", "blue")
            return
        
        try:
            packet = json.loads(self.last_honest_packet)
            
            # Tamper with ciphertext
            ct_bytes = base64.b64decode(packet["ciphertext"])
            tampered_ct = bytes([(b + 1) % 256 for b in ct_bytes[:10]]) + ct_bytes[10:]
            packet["ciphertext"] = base64.b64encode(tampered_ct).decode('utf-8')
            
            tampered_json = json.dumps(packet)
            
            self.log("\n[ATTACK] Attempting TAMPERING attack...", "orange")
            self.packet_text.text += f"\n[TAMPERING ATTACK - Modified ciphertext]\n"
            self.process_packet_with_security(tampered_json)
            
        except Exception as e:
            self.log(f"[ERROR] Tampering simulation failed: {e}", "red")
    
    def simulate_mitm_attack(self, instance):
        """Simulate MITM attack"""
        if not self.last_honest_packet:
            self.log("[INFO] Send a message first", "blue")
            return
        
        try:
            packet = json.loads(self.last_honest_packet)
            
            # Replace sender's public key with attacker's
            attacker_pub_pem = export_public_key_pem(self.attacker_pub)
            packet["sender_public_key"] = base64.b64encode(attacker_pub_pem).decode('utf-8')
            
            # Re-sign with attacker's key
            iv = base64.b64decode(packet["iv"])
            ct = base64.b64decode(packet["ciphertext"])
            timestamp = str(packet.get("timestamp", time.time())).encode('utf-8')
            message_id = packet.get("message_id", str(uuid.uuid4())).encode('utf-8')
            
            to_sign = iv + ct + timestamp + message_id
            new_sig = sign_message(self.attacker_priv, to_sign)
            packet["signature"] = base64.b64encode(new_sig).decode('utf-8')
            
            mitm_json = json.dumps(packet)
            
            self.log("\n[ATTACK] Attempting MITM attack...", "orange")
            self.packet_text.text += f"\n[MITM ATTACK - Replaced public key]\n"
            self.process_packet_with_security(mitm_json)
            
        except Exception as e:
            self.log(f"[ERROR] MITM simulation failed: {e}", "red")
    
    def simulate_iv_reuse_attack(self, instance):
        """Simulate IV reuse attack"""
        if not self.last_honest_packet:
            self.log("[INFO] Send a message first", "blue")
            return
        
        try:
            # Create new message with reused IV
            packet = json.loads(self.last_honest_packet)
            old_iv = packet["iv"]
            
            # Create new message but reuse IV
            new_plaintext = "This message reuses an IV!"
            new_packet = json.loads(self.messenger.create_secure_message_packet(new_plaintext))
            new_packet["iv"] = old_iv  # Reuse the IV
            
            reuse_json = json.dumps(new_packet)
            
            self.log("\n[ATTACK] Attempting IV REUSE attack...", "orange")
            self.packet_text.text += f"\n[IV REUSE ATTACK - Same IV with different message]\n"
            self.process_packet_with_security(reuse_json)
            
        except Exception as e:
            self.log(f"[ERROR] IV reuse simulation failed: {e}", "red")
    
    def log(self, message: str, color: str = "black"):
        """Add message to security log with color"""
        color_map = {
            "red": "[color=ff0000]",
            "green": "[color=008800]",
            "blue": "[color=0000ff]",
            "orange": "[color=ff8800]",
            "black": "[color=000000]"
        }
        
        prefix = color_map.get(color, "[color=000000]")
        self.log_text.text += f"{prefix}{message}[/color]\n"
    
    def show_popup(self, title: str, message: str):
        """Show a popup message"""
        content = BoxLayout(orientation='vertical', padding=10)
        content.add_widget(Label(text=message))
        
        popup = Popup(
            title=title,
            content=content,
            size_hint=(0.8, 0.3)
        )
        
        close_btn = Button(text='Close', size_hint=(1, 0.3))
        close_btn.bind(on_press=popup.dismiss)
        content.add_widget(close_btn)
        
        popup.open()
    
    def on_stop(self):
        """Clean up when app closes"""
        if hasattr(self, 'security_state'):
            # Get and log statistics
            stats = self.security_state.get_statistics()
            print(f"Security Statistics: {stats}")
            self.security_state.close()


# Need serialization import
from cryptography.hazmat.primitives import serialization


if __name__ == "__main__":
    EnhancedSecureMessengerApp().run()