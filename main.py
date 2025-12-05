# main_kivy.py
# Kivy-based "mobile" secure messenger for ICS344, using existing AES/RSA code.

import json
import base64

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.scrollview import ScrollView

from aes_cbc import generate_aes_key, encrypt_aes_cbc_with_iv, decrypt_aes_cbc, IV_SIZE
from rsa_sign import (
    generate_rsa_keypair,
    sign_message,
    verify_signature,
    export_public_key_pem,
)
from secure_message_demo import sender_create_packet


class SecureMessengerApp(App):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Crypto setup: same as Tkinter version
        self.aes_key = generate_aes_key()
        self.sender_priv, self.sender_pub = generate_rsa_keypair(2048)
        self.attacker_priv, self.attacker_pub = generate_rsa_keypair(2048)

        # For attacks / mitigations
        self.last_sent_packet = None
        self.last_honest_packet = None
        self.last_honest_plaintext = None
        self.seen_packets = set()  # replay detection
        self.seen_ivs = set()      # IV reuse detection

        # UI widgets (assigned in build)
        self.recv_text = None
        self.packet_text = None
        self.log_text = None
        self.input_text = None

    def build(self):
        self.title = "Secure Mobile Messenger - ICS344"

        # Root: phone-like vertical layout
        root = BoxLayout(orientation="vertical", padding=6, spacing=4)

        # ===== Header =====
        header = BoxLayout(size_hint_y=None, height=40)
        header.add_widget(Label(text="Secure Chat (Mobile Prototype)", bold=True))
        root.add_widget(header)

        # ===== Receiver view =====
        recv_box = BoxLayout(orientation="vertical", size_hint_y=0.22)
        recv_box.add_widget(Label(text="Received (receiver view)", size_hint_y=None, height=20))

        self.recv_text = TextInput(
            readonly=True,
            multiline=True,
            font_size=14,
        )
        recv_box.add_widget(self.recv_text)
        root.add_widget(recv_box)

        # ===== Network packet =====
        packet_box = BoxLayout(orientation="vertical", size_hint_y=0.28)
        packet_box.add_widget(Label(text="Encrypted Packet (network view)", size_hint_y=None, height=20))

        self.packet_text = TextInput(
            multiline=True,
            font_size=11,
        )
        packet_box.add_widget(self.packet_text)
        root.add_widget(packet_box)

        # ===== Attacker / debug panel =====
        attack_box = BoxLayout(orientation="vertical", size_hint_y=None, height=110)
        attack_box.add_widget(Label(
            text="Attacker / Debug Panel (for demo)",
            size_hint_y=None,
            height=20,
            color=(1, 0.4, 0, 1),
        ))

        attack_buttons = BoxLayout(size_hint_y=None, height=40, spacing=4)
        btn_tamper = Button(text="Tamper", on_press=lambda *_: self.on_attack_tamper_ciphertext())
        btn_replay = Button(text="Replay", on_press=lambda *_: self.on_replay_attack())
        btn_mitm = Button(text="MITM Key", on_press=lambda *_: self.on_mitm_attack())
        btn_iv = Button(text="IV Reuse", on_press=lambda *_: self.on_iv_reuse_attack())
        attack_buttons.add_widget(btn_tamper)
        attack_buttons.add_widget(btn_replay)
        attack_buttons.add_widget(btn_mitm)
        attack_buttons.add_widget(btn_iv)
        attack_box.add_widget(attack_buttons)

        root.add_widget(attack_box)

        # ===== Security log =====
        log_box = BoxLayout(orientation="vertical", size_hint_y=0.25)
        log_box.add_widget(Label(text="Security Log", size_hint_y=None, height=20))

        self.log_text = TextInput(
            readonly=True,
            multiline=True,
            font_size=11,
        )
        log_box.add_widget(self.log_text)
        root.add_widget(log_box)

        # ===== Compose bar (bottom like chat input) =====
        compose_box = BoxLayout(orientation="vertical", size_hint_y=0.25, spacing=2)

        self.input_text = TextInput(
            multiline=True,
            font_size=14,
            hint_text="Type message here...",
            size_hint_y=0.7,
        )
        compose_box.add_widget(self.input_text)

        btn_row = BoxLayout(size_hint_y=0.3, spacing=4)
        btn_send = Button(text="Send Securely", on_press=lambda *_: self.on_encrypt_send())
        btn_recv = Button(text="Receive / Verify", on_press=lambda *_: self.on_verify_decrypt())
        btn_row.add_widget(btn_send)
        btn_row.add_widget(btn_recv)

        compose_box.add_widget(btn_row)
        root.add_widget(compose_box)

        # Initial logs
        self.log("App started. AES key + RSA keypair generated.")
        self.log("Attacker RSA keypair also generated for MITM demo.")
        self.log("Receiver pins the real sender public key (MITM mitigation).")

        # Make window narrow/tall like a phone
        from kivy.core.window import Window
        Window.size = (430, 780)

        return root

    # ===== helper logging =====
    def log(self, msg: str):
        if not self.log_text:
            return
        self.log_text.text += msg + "\n"
        self.log_text.cursor = (0, len(self.log_text.text))

    # ===== honest sender =====
    def on_encrypt_send(self):
        plaintext = (self.input_text.text or "").strip()
        if not plaintext:
            self.log("No plaintext to send.")
            return

        try:
            packet_json = sender_create_packet(
                self.aes_key,
                self.sender_priv,
                self.sender_pub,
                plaintext,
            )
            self.packet_text.text = packet_json

            self.last_sent_packet = packet_json
            self.last_honest_packet = packet_json
            self.last_honest_plaintext = plaintext

            self.log("Message encrypted + signed. Packet ready on the network.")
        except Exception as e:
            self.log(f"[ERROR] Encrypt+Sign failed: {e}")

    # ===== honest receiver (with mitigations) =====
    def on_verify_decrypt(self):
        packet_json = (self.packet_text.text or "").strip()
        if not packet_json:
            self.log("No packet to process.")
            return

        # Replay protection
        if packet_json in self.seen_packets:
            self.log("[REPLAY DETECTED] Packet was already processed before. Dropping it.")
            return

        # Parse JSON
        try:
            packet = json.loads(packet_json)
        except json.JSONDecodeError:
            self.log("[ERROR] Packet is not valid JSON.")
            return

        iv_str = packet.get("iv")
        ct_str = packet.get("ciphertext")
        sig_str = packet.get("signature")
        if not iv_str or not ct_str or not sig_str:
            self.log("[ERROR] Packet missing iv/ciphertext/signature.")
            return

        # Decode base64
        try:
            iv_bytes = base64.b64decode(iv_str.encode("ascii"))
            ct_bytes = base64.b64decode(ct_str.encode("ascii"))
            sig_bytes = base64.b64decode(sig_str.encode("ascii"))
        except Exception:
            self.log("[ERROR] Base64 decoding failed.")
            return

        to_verify = iv_bytes + ct_bytes

        # MITM mitigation: pinned sender_pub
        if not verify_signature(self.sender_pub, to_verify, sig_bytes):
            self.log("[SECURITY WARNING] Signature invalid with pinned sender key.")
            self.log("  => Possible tampering or MITM key-substitution. Dropping packet.")
            return

        # IV reuse mitigation
        if iv_bytes in self.seen_ivs:
            self.log("[IV REUSE DETECTED] Same IV used again with this AES key. Dropping packet.")
            return
        else:
            self.seen_ivs.add(iv_bytes)

        # Decrypt
        try:
            plaintext_bytes = decrypt_aes_cbc(self.aes_key, iv_bytes, ct_bytes)
            plaintext = plaintext_bytes.decode("utf-8")
        except Exception as e:
            self.log(f"[ERROR] Decryption failed: {e}")
            return

        self.seen_packets.add(packet_json)
        self.recv_text.text = plaintext
        self.log("Signature valid with pinned key. Ciphertext decrypted successfully.")

    # ===== Attack 1: ciphertext tampering =====
    def on_attack_tamper_ciphertext(self):
        packet_json = (self.packet_text.text or "").strip()
        if not packet_json:
            self.log("No packet to tamper with.")
            return

        try:
            packet = json.loads(packet_json)
        except json.JSONDecodeError:
            self.log("[Tamper Attack] Packet JSON invalid; cannot tamper.")
            return

        ct_str = packet.get("ciphertext")
        if not ct_str:
            self.log("[Tamper Attack] No 'ciphertext' field.")
            return

        ct_list = list(ct_str)
        for i, ch in enumerate(ct_list):
            if ch != "=":
                ct_list[i] = "A" if ch != "A" else "B"
                break
        packet["ciphertext"] = "".join(ct_list)

        self.packet_text.text = json.dumps(packet)
        self.log("[Tamper Attack] Ciphertext modified in packet.")
        self.log("Next Receive/Verify should FAIL signature check.")

    # ===== Attack 2: replay =====
    def on_replay_attack(self):
        if not self.last_sent_packet:
            self.log("[Replay Attack] No previous packet stored.")
            return
        self.log("[Replay Attack] Attacker resends previously sent packet.")
        self.packet_text.text = self.last_sent_packet
        self.on_verify_decrypt()

    # ===== Attack 3: MITM key substitution =====
    def on_mitm_attack(self):
        packet_json = (self.packet_text.text or "").strip()
        if not packet_json:
            self.log("[MITM Attack] No packet to modify.")
            return

        try:
            packet = json.loads(packet_json)
        except json.JSONDecodeError:
            self.log("[MITM Attack] Packet JSON invalid; cannot MITM.")
            return

        iv_str = packet.get("iv")
        ct_str = packet.get("ciphertext")
        if not iv_str or not ct_str:
            self.log("[MITM Attack] Packet missing iv/ciphertext.")
            return

        iv_bytes = base64.b64decode(iv_str.encode("ascii"))
        ct_bytes = base64.b64decode(ct_str.encode("ascii"))
        to_sign = iv_bytes + ct_bytes

        signature = sign_message(self.attacker_priv, to_sign)
        attacker_pub_pem = export_public_key_pem(self.attacker_pub)

        packet["signature"] = base64.b64encode(signature).decode("ascii")
        packet["sender_public_key"] = base64.b64encode(attacker_pub_pem).decode("ascii")

        self.packet_text.text = json.dumps(packet)
        self.log("[MITM Attack] Replaced signature and sender_public_key with ATTACKER values.")
        self.log("Pinned-key verify will now REJECT this packet.")

    # ===== Attack 4: IV reuse =====
    def on_iv_reuse_attack(self):
        if not self.last_honest_packet or not self.last_honest_plaintext:
            self.log("[IV Reuse Attack] Need at least one honest message first.")
            return

        new_plaintext = (self.input_text.text or "").strip()
        if not new_plaintext:
            self.log("[IV Reuse Attack] Type a NEW message first.")
            return

        try:
            packet1 = json.loads(self.last_honest_packet)
        except json.JSONDecodeError:
            self.log("[IV Reuse Attack] Stored honest packet invalid.")
            return

        iv_str = packet1.get("iv")
        ct1_str = packet1.get("ciphertext")
        if not iv_str or not ct1_str:
            self.log("[IV Reuse Attack] Stored packet missing iv/ciphertext.")
            return

        iv_bytes = base64.b64decode(iv_str.encode("ascii"))
        ct1_bytes = base64.b64decode(ct1_str.encode("ascii"))

        pt2_bytes = new_plaintext.encode("utf-8")
        ct2_bytes = encrypt_aes_cbc_with_iv(self.aes_key, pt2_bytes, iv_bytes)

        to_sign2 = iv_bytes + ct2_bytes
        sig2 = sign_message(self.sender_priv, to_sign2)
        sender_pub_pem = export_public_key_pem(self.sender_pub)

        packet2 = {
            "iv": iv_str,
            "ciphertext": base64.b64encode(ct2_bytes).decode("ascii"),
            "signature": base64.b64encode(sig2).decode("ascii"),
            "sender_public_key": base64.b64encode(sender_pub_pem).decode("ascii"),
        }

        self.packet_text.text = json.dumps(packet2)
        self.last_sent_packet = self.packet_text.text

        # Show why reuse is bad
        block1_ct1 = ct1_bytes[:IV_SIZE]
        block1_ct2 = ct2_bytes[:IV_SIZE]
        prefix1 = base64.b64encode(block1_ct1).decode("ascii")
        prefix2 = base64.b64encode(block1_ct2).decode("ascii")

        self.log("[IV Reuse Attack] Reused IV from previous honest message.")
        self.log(f"  IV (base64): {iv_str}")
        self.log(f"  First block old ciphertext: {prefix1}")
        self.log(f"  First block new ciphertext: {prefix2}")
        self.log(f"  Equal first blocks? {prefix1 == prefix2}")


if __name__ == "__main__":
    SecureMessengerApp().run()
