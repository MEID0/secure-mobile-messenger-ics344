"""
Persistent Security State Management
Stores and retrieves security tracking data across sessions
ICS344 - Group P26
"""

import json
import sqlite3
import hashlib
from datetime import datetime, timedelta
from typing import Set, Optional, Tuple
import os
import time

class SecurityStateManager:
    """Manages persistent security state using SQLite"""
    
    def __init__(self, db_path: str = "security_state.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.init_database()
        
    def init_database(self):
        """Create necessary tables if they don't exist"""
        cursor = self.conn.cursor()
        
        # Table for tracking processed packets
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS processed_packets (
                packet_hash TEXT PRIMARY KEY,
                timestamp REAL,
                sender_key_hash TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Table for tracking used IVs per AES key
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS used_ivs (
                iv_hex TEXT,
                aes_key_hash TEXT,
                timestamp REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (iv_hex, aes_key_hash)
            )
        ''')
        
        # Table for tracking message timestamps
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS message_timestamps (
                message_id TEXT PRIMARY KEY,
                timestamp REAL,
                processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.conn.commit()
    
    def has_packet_been_processed(self, packet_json: str) -> bool:
        """Check if packet was already processed"""
        packet_hash = hashlib.sha256(packet_json.encode()).hexdigest()
        
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT 1 FROM processed_packets WHERE packet_hash = ?",
            (packet_hash,)
        )
        
        return cursor.fetchone() is not None
    
    def mark_packet_processed(self, packet_json: str, sender_key: str):
        """Mark packet as processed"""
        packet_hash = hashlib.sha256(packet_json.encode()).hexdigest()
        sender_hash = hashlib.sha256(sender_key.encode()).hexdigest()
        
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT OR IGNORE INTO processed_packets (packet_hash, timestamp, sender_key_hash) VALUES (?, ?, ?)",
            (packet_hash, datetime.now().timestamp(), sender_hash)
        )
        self.conn.commit()
    
    def has_iv_been_used(self, iv_bytes: bytes, aes_key: bytes) -> bool:
        """Check if IV was already used with this AES key"""
        iv_hex = iv_bytes.hex()
        key_hash = hashlib.sha256(aes_key).hexdigest()
        
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT 1 FROM used_ivs WHERE iv_hex = ? AND aes_key_hash = ?",
            (iv_hex, key_hash)
        )
        
        return cursor.fetchone() is not None
    
    def mark_iv_used(self, iv_bytes: bytes, aes_key: bytes):
        """Mark IV as used with this AES key"""
        iv_hex = iv_bytes.hex()
        key_hash = hashlib.sha256(aes_key).hexdigest()
        
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT OR IGNORE INTO used_ivs (iv_hex, aes_key_hash, timestamp) VALUES (?, ?, ?)",
            (iv_hex, key_hash, datetime.now().timestamp())
        )
        self.conn.commit()
    
    def check_timestamp_validity(self, message_id: str, timestamp: float, window_seconds: int = 300) -> Tuple[bool, str]:
        """
        Check if message timestamp is within acceptable window
        
        Args:
            message_id: Unique message identifier
            timestamp: Message timestamp
            window_seconds: Acceptable time window (default 5 minutes)
        
        Returns:
            Tuple of (is_valid, reason)
        """
        current_time = datetime.now().timestamp()
        
        # Check if timestamp is in the future
        if timestamp > current_time + 60:  # Allow 1 minute clock skew
            return False, "Timestamp is in the future"
        
        # Check if timestamp is too old
        if current_time - timestamp > window_seconds:
            return False, f"Timestamp older than {window_seconds} seconds"
        
        # Check if we've seen this message ID before
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT timestamp FROM message_timestamps WHERE message_id = ?",
            (message_id,)
        )
        result = cursor.fetchone()
        
        if result:
            return False, "Duplicate message ID"
        
        # Record this message
        cursor.execute(
            "INSERT INTO message_timestamps (message_id, timestamp) VALUES (?, ?)",
            (message_id, timestamp)
        )
        self.conn.commit()
        
        return True, "Valid timestamp"
    
    def cleanup_old_records(self, days: int = 7):
        """Remove records older than specified days"""
        cutoff = datetime.now() - timedelta(days=days)
        cutoff_timestamp = cutoff.timestamp()
        
        cursor = self.conn.cursor()
        
        # Clean up old packets
        cursor.execute(
            "DELETE FROM processed_packets WHERE timestamp < ?",
            (cutoff_timestamp,)
        )
        
        # Clean up old IVs
        cursor.execute(
            "DELETE FROM used_ivs WHERE timestamp < ?",
            (cutoff_timestamp,)
        )
        
        # Clean up old timestamps
        cursor.execute(
            "DELETE FROM message_timestamps WHERE timestamp < ?",
            (cutoff_timestamp,)
        )
        
        self.conn.commit()
    
    def get_statistics(self) -> dict:
        """Get security state statistics"""
        cursor = self.conn.cursor()
        
        stats = {}
        
        cursor.execute("SELECT COUNT(*) FROM processed_packets")
        stats['total_packets'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM used_ivs")
        stats['total_ivs'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM message_timestamps")
        stats['total_messages'] = cursor.fetchone()[0]
        
        return stats
    
    def close(self):
        """Close database connection"""
        self.conn.close()