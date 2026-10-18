"""
Kyberon 4.1.0 - Zero-Trust, Post-Quantum Cryptographic Suite & Secure P2P Ecosystem
Features:
1. Multi-User Profiles (Isolated credentials and encrypted storage per user/machine)
2. Hardware-Bound Profiles (Hardware fingerprint binding - vault cannot be opened on other PCs)
3. Live P2P Encrypted Chat Network (Worldwide end-to-end AES-256-GCM + Ed25519 relay)
4. Air-Gapped Optical QR Cryptography (OpenCV computer vision + high-density QR)
5. Blockchain-Verified Live Cold Storage Portfolio (Blockchain.info API + Binance rates)
6. Automatic GitHub Releases Update Detection (SHA-256 + PE Header Verified)
7. Trilingual Localization (Turkish, English, Russian)
8. FIPS 140-3 Power-On Self-Tests (POST) and HMAC-Authenticated Merkle Audit Trail
"""

import os
import sys
import time
import base64
import json
import secrets
import threading
import customtkinter as ctk
from tkinter import messagebox, filedialog
from PIL import Image

import i18n
from i18n import get_text
import vault_storage
import crypto_utils
import crypto_portfolio
import live_p2p_chat
import airgap_crypto
import updater
import military_audit
import steganography
from military_vault import VaultSecurityError

# Ensure consistent working directory regardless of how the application is launched
if getattr(sys, 'frozen', False):
    os.chdir(os.path.dirname(os.path.abspath(sys.executable)))
else:
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class KyberonApp(ctk.CTk):
    INACTIVITY_TIMEOUT = 120  # 2 minutes auto-lock timeout

    def __init__(self):
        super().__init__()

        self.title("Kyberon 4.1.0 - Zero-Trust Cryptographic Suite & P2P")
        self.geometry("1120x760")
        self.minsize(980, 660)

        # Core State Variables
        self.selected_profile = "Varsayılan"
        self.master_password = None
        self.effective_password = None
        self.vault_data = None
        self.is_decoy = False
        self.revealed_secrets = set()
        self.last_activity_time = time.time()
        self.current_tab = "vault"
        self.live_prices = crypto_portfolio.DEFAULT_PRICES

        # Persistent P2P Chat State (W-01: No hardcoded default room/passkey in source)
        self.p2p_session = None
        self.p2p_message_history = []  # Stores message dicts
        self.p2p_saved_nick = ""
        self.p2p_saved_room = ""
        self.p2p_saved_key = ""
        self.p2p_burn_enabled = False
        self.p2p_status_text = ""

        # Run FIPS 140-3 Power-On Self-Tests (V-11: Fail-Closed enforcement & truthful audit log)
        self.post_results = military_audit.run_power_on_self_tests()
        if self.post_results.get("all_passed", False):
            military_audit.CryptographicAuditTrail.record_event(
                "POST_BOOT", "System", "FIPS 140-3 Power-On Self Tests 100% Passed (NIST KAT 100%)", "INFO"
            )
        else:
            failed_tests = [t.get("name", "Unknown") for t in self.post_results.get("tests", []) if not t.get("passed", False)]
            military_audit.CryptographicAuditTrail.record_event(
                "POST_BOOT_FAILURE",
                "System",
                f"CRITICAL: FIPS 140-3 Power-On Self-Tests FAILED: {', '.join(failed_tests)}",
                "CRITICAL"
            )
            messagebox.showerror(
                "FIPS 140-3 POST Failure",
                f"CRITICAL: Cryptographic Power-On Self-Tests FAILED ({', '.join(failed_tests)}).\nOperation halted (Fail-Closed)."
            )
            raise RuntimeError(f"FIPS 140-3 Power-On Self-Test failed: {', '.join(failed_tests)}")

        # Root Container
        self.container = ctk.CTkFrame(self, corner_radius=0)
        self.container.pack(fill="both", expand=True)

        # Intercept inputs and enforce Panic Hotkey across all widgets and layouts
        self.bind_all("<Key>", self._on_global_key_press)
        self.bind_all("<Motion>", self._on_user_interaction)
        self.bind_all("<Button>", self._on_user_interaction)
        self.bind_all("<Control-Shift-Key-L>", lambda e: self.lock_vault(reason="Emergency Panic Lock Triggered"))
        self.bind_all("<Control-Shift-Key-l>", lambda e: self.lock_vault(reason="Emergency Panic Lock Triggered"))
        self.bind_all("<Control-Key-L>", lambda e: self.lock_vault(reason="Emergency Panic Lock Triggered"))
        self.bind_all("<Control-Key-l>", lambda e: self.lock_vault(reason="Emergency Panic Lock Triggered"))

        self.check_vault_status()
        self._start_inactivity_timer()
        self._start_price_fetch_thread()
        self._start_global_windows_hotkey()

    def _on_global_key_press(self, event=None):
        """Monitors key events, resets user interaction timer, and intercepts Panic Hotkey (Ctrl+Shift+L)."""
        self._on_user_interaction(event)
        if event:
            # Control (bit 4) and Shift (bit 1)
            ctrl_down = bool(event.state & 4)
            shift_down = bool(event.state & 1)
            # Physical key 'L' is virtual keycode 76 on Windows across all keyboard layouts (Turkish, Russian, etc.)
            is_l_key = (getattr(event, "keycode", 0) == 76) or (getattr(event, "keysym", "").lower() in ("l", "cyrillic_de", "cyrillic_el"))
            if ctrl_down and shift_down and is_l_key:
                if self.master_password:
                    self.lock_vault(reason="Emergency Panic Lock Triggered (Ctrl+Shift+L)")

    def _start_global_windows_hotkey(self):
        """Registers a system-wide OS-level Ctrl+Shift+L hotkey on Windows so panic lock works even when in background."""
        if os.name != "nt":
            return
        def hotkey_worker():
            try:
                import ctypes
                from ctypes import wintypes
                user32 = ctypes.windll.user32
                MOD_CONTROL = 0x0002
                MOD_SHIFT = 0x0004
                MOD_NOREPEAT = 0x4000
                VK_L = 0x4C
                HOTKEY_ID = 9999

                success = user32.RegisterHotKey(None, HOTKEY_ID, MOD_CONTROL | MOD_SHIFT | MOD_NOREPEAT, VK_L)
                if not success:
                    success = user32.RegisterHotKey(None, HOTKEY_ID, MOD_CONTROL | MOD_SHIFT, VK_L)
                if not success:
                    return

                msg = wintypes.MSG()
                while True:
                    res = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                    if res == -1 or res == 0:
                        break
                    if msg.message == 0x0312:  # WM_HOTKEY
                        if msg.wParam == HOTKEY_ID:
                            if self.master_password:
                                self.after(0, lambda: self.lock_vault(reason="Emergency Panic Lock Triggered (Global Ctrl+Shift+L)"))
                    user32.TranslateMessage(ctypes.byref(msg))
                    user32.DispatchMessageW(ctypes.byref(msg))
                user32.UnregisterHotKey(None, HOTKEY_ID)
            except Exception:
                pass

        threading.Thread(target=hotkey_worker, daemon=True).start()

    def _on_user_interaction(self, event=None):
        """Resets user inactivity timer on input interaction."""
        self.last_activity_time = time.time()

    def _start_inactivity_timer(self):
        """Enforces auto-lock policy after period of inactivity."""
        if self.master_password and (time.time() - self.last_activity_time > self.INACTIVITY_TIMEOUT):
            self.lock_vault(reason=get_text("inactivity_notice"))
        self.after(5000, self._start_inactivity_timer)

    def _start_price_fetch_thread(self):
        """Asynchronously fetches live cryptocurrency prices in the background."""
        def worker():
            try:
                self.live_prices = crypto_portfolio.fetch_live_prices()
                if self.current_tab == "portfolio" and hasattr(self, "main_content"):
                    self.after(0, self.render_active_tab)
            except Exception:
                pass
        threading.Thread(target=worker, daemon=True).start()

    def clear_container(self):
        """Destroys all child widgets of the main container."""
        for widget in self.container.winfo_children():
            widget.destroy()

    def set_language_and_refresh(self, lang_choice: str):
        """Switches active language and refreshes UI components immediately."""
        lang_code = "tr"
        if "English" in lang_choice or "en" in lang_choice.lower():
            lang_code = "en"
        elif "Русский" in lang_choice or "ru" in lang_choice.lower():
            lang_code = "ru"

        i18n.set_language(lang_code)
        if self.vault_data and self.master_password:
            self.vault_data.setdefault("settings", {})["language"] = lang_code
            vault_storage.save_vault(self.effective_password or self.master_password, self.vault_data, is_decoy=self.is_decoy)
            self.show_dashboard()
        else:
            self.check_vault_status()

    # =========================================================================
    # 1. INITIALIZATION & PROFILE SELECTION / LOGIN SCREEN
    # =========================================================================
    def check_vault_status(self):
        """Checks for existing profiles and presents either login or profile creation."""
        self.clear_container()
        profiles = vault_storage.list_profiles()
        if not profiles or (len(profiles) == 1 and not vault_storage.profile_exists(profiles[0])):
            self.show_create_profile_screen()
        else:
            self.show_unlock_screen()

    def _add_top_lang_selector(self, parent_frame):
        """Renders language switcher dropdown in top right corner of authentication screens."""
        lang_bar = ctk.CTkFrame(parent_frame, fg_color="transparent")
        lang_bar.pack(anchor="ne", padx=20, pady=(15, 0))

        lang_menu = ctk.CTkOptionMenu(
            lang_bar,
            values=["🇹🇷 Türkçe", "🇬🇧 English", "🇷🇺 Русский"],
            width=130,
            height=28,
            font=ctk.CTkFont(size=11),
            command=self.set_language_and_refresh
        )
        cur = i18n.CURRENT_LANG
        lang_menu.set(i18n.LANGUAGES.get(cur, "🇹🇷 Türkçe"))
        lang_menu.pack(side="right")

    def show_create_profile_screen(self):
        """Displays initial profile creation and master password configuration screen."""
        self.clear_container()
        self._add_top_lang_selector(self.container)

        frame = ctk.CTkFrame(self.container, width=540, corner_radius=15, fg_color="#181a1f")
        frame.place(relx=0.5, rely=0.52, anchor="center")

        title_lbl = ctk.CTkLabel(
            frame,
            text=get_text("setup_title"),
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="#38bdf8"
        )
        title_lbl.pack(pady=(25, 6), padx=30)

        desc_lbl = ctk.CTkLabel(
            frame,
            text=get_text("setup_desc"),
            font=ctk.CTkFont(size=12),
            text_color="#94a3b8",
            justify="center"
        )
        desc_lbl.pack(pady=(0, 15), padx=25)

        self.setup_prof_entry = ctk.CTkEntry(
            frame, placeholder_text=get_text("profile_name_placeholder"), width=400, height=40
        )
        self.setup_prof_entry.pack(pady=5)
        self.setup_prof_entry.insert(0, "Kisisel")

        self.setup_pass_entry = ctk.CTkEntry(
            frame, placeholder_text=get_text("master_pass_placeholder"), show="*", width=400, height=40
        )
        self.setup_pass_entry.pack(pady=5)

        self.setup_pass_confirm = ctk.CTkEntry(
            frame, placeholder_text=get_text("confirm_pass_placeholder"), show="*", width=400, height=40
        )
        self.setup_pass_confirm.pack(pady=5)

        self.setup_duress_entry = ctk.CTkEntry(
            frame, placeholder_text=get_text("duress_pass_placeholder"), show="*", width=400, height=40
        )
        self.setup_duress_entry.pack(pady=5)

        # Hardware Fingerprint Binding Checkbox
        self.hw_bind_var = ctk.BooleanVar(value=False)
        hw_chk = ctk.CTkCheckBox(
            frame,
            text=get_text("bind_hw_label"),
            variable=self.hw_bind_var,
            font=ctk.CTkFont(size=11),
            text_color="#38bdf8"
        )
        hw_chk.pack(pady=(6, 4))

        # 2FA USB Keyfile / Hardware Token Controls
        self.selected_keyfile_path = None
        kf_row = ctk.CTkFrame(frame, fg_color="transparent")
        kf_row.pack(pady=2)

        kf_status_lbl = ctk.CTkLabel(
            frame,
            text=get_text("keyfile_none_lbl"),
            font=ctk.CTkFont(size=11),
            text_color="#94a3b8"
        )

        def pick_setup_keyfile():
            fpath = filedialog.askopenfilename(
                title=get_text("keyfile_select_btn"),
                filetypes=[("Kyberon 2FA Keyfile", "*.kkey;*.akey"), ("All Files", "*.*")]
            )
            if fpath:
                self.selected_keyfile_path = fpath
                kf_status_lbl.configure(
                    text=get_text("keyfile_selected_lbl", fname=os.path.basename(fpath)),
                    text_color="#4ade80"
                )

        def generate_new_keyfile():
            dest = filedialog.asksaveasfilename(
                defaultextension=".akey",
                initialfile="kyberon_2fa_token.kkey",
                filetypes=[("Kyberon 2FA Keyfile", "*.kkey;*.akey")],
                title=get_text("keyfile_gen_btn")
            )
            if dest:
                digest = vault_storage.generate_keyfile(dest)
                self.selected_keyfile_path = dest
                kf_status_lbl.configure(
                    text=get_text("keyfile_selected_lbl", fname=os.path.basename(dest)),
                    text_color="#4ade80"
                )
                messagebox.showinfo(
                    "2FA Keyfile Ready",
                    get_text("keyfile_gen_success", path=dest, digest=digest[:16])
                )

        ctk.CTkButton(
            kf_row,
            text=get_text("keyfile_select_btn"),
            fg_color="#1e293b",
            hover_color="#334155",
            text_color="#38bdf8",
            height=28,
            width=195,
            font=ctk.CTkFont(size=11),
            command=pick_setup_keyfile
        ).pack(side="left", padx=3)

        ctk.CTkButton(
            kf_row,
            text=get_text("keyfile_gen_btn"),
            fg_color="#065f46",
            hover_color="#047857",
            text_color="#a7f3d0",
            height=28,
            width=195,
            font=ctk.CTkFont(size=11),
            command=generate_new_keyfile
        ).pack(side="left", padx=3)

        kf_status_lbl.pack(pady=(0, 4))

        gen_btn = ctk.CTkButton(
            frame,
            text=get_text("btn_suggest_pass"),
            fg_color="#334155",
            hover_color="#475569",
            text_color="#38bdf8",
            command=self._generate_suggested_master_pass,
            height=30
        )
        gen_btn.pack(pady=4)

        btn_box = ctk.CTkFrame(frame, fg_color="transparent")
        btn_box.pack(pady=(8, 20), fill="x", padx=35)

        create_btn = ctk.CTkButton(
            btn_box,
            text=get_text("btn_create_vault"),
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            height=42,
            command=self._handle_create_profile
        )
        create_btn.pack(fill="x")

        # Back to existing profiles if any exist
        if vault_storage.list_profiles():
            cancel_btn = ctk.CTkButton(
                btn_box,
                text=get_text("btn_back_profiles"),
                fg_color="transparent",
                text_color="#94a3b8",
                hover_color="#334155",
                command=self.show_unlock_screen,
                height=28
            )
            cancel_btn.pack(pady=(6, 0))

    def _generate_suggested_master_pass(self):
        new_pass = vault_storage.generate_secure_password(length=28, use_symbols=True)
        self.setup_pass_entry.delete(0, "end")
        self.setup_pass_confirm.delete(0, "end")
        self.setup_pass_entry.insert(0, new_pass)
        self.setup_pass_confirm.insert(0, new_pass)
        self.setup_pass_entry.configure(show="")
        self.setup_pass_confirm.configure(show="")
        self.clipboard_clear()
        self.clipboard_append(new_pass)
        messagebox.showinfo(get_text("copied_alert"), new_pass)

    def _handle_create_profile(self):
        prof = self.setup_prof_entry.get().strip()
        p1 = self.setup_pass_entry.get().strip()
        p2 = self.setup_pass_confirm.get().strip()
        duress = self.setup_duress_entry.get().strip()
        bind_hw = self.hw_bind_var.get()
        kf_path = getattr(self, "selected_keyfile_path", None)

        if not prof:
            messagebox.showerror("Error", "Please enter a profile name!")
            return
        if len(p1) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters!")
            return
        if p1 != p2:
            messagebox.showerror("Error", "Passwords do not match!")
            return
        if duress and duress == p1:
            messagebox.showerror("Error", "Duress password cannot be identical to master password!")
            return

        self.selected_profile = prof
        self.master_password = p1
        self.is_decoy = False

        self.vault_data = vault_storage.init_vault(
            master_password=p1,
            duress_password=duress if duress else None,
            lang=i18n.CURRENT_LANG,
            profile_name=prof,
            bind_to_hardware=bind_hw,
            keyfile_path=kf_path
        )
        eff = p1
        if bind_hw:
            eff += f"|HW:{vault_storage.get_hardware_fingerprint()}"
        if kf_path:
            eff += f"|KF:{vault_storage.compute_keyfile_digest(kf_path)}"
        self.effective_password = eff
        self.show_dashboard()

    def show_unlock_screen(self):
        """Displays password entry screen for unlocking an existing vault profile."""
        self.clear_container()
        self._add_top_lang_selector(self.container)
        self.selected_keyfile_path = None

        frame = ctk.CTkFrame(self.container, width=500, corner_radius=15, fg_color="#181a1f")
        frame.place(relx=0.5, rely=0.52, anchor="center")

        title_lbl = ctk.CTkLabel(
            frame,
            text=get_text("unlock_title"),
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#38bdf8"
        )
        title_lbl.pack(pady=(26, 6), padx=30)

        info_lbl = ctk.CTkLabel(
            frame,
            text=get_text("unlock_desc"),
            font=ctk.CTkFont(size=12),
            text_color="#94a3b8",
            justify="center"
        )
        info_lbl.pack(pady=(0, 14), padx=25)

        # Profile Selector
        prof_frame = ctk.CTkFrame(frame, fg_color="transparent")
        prof_frame.pack(fill="x", padx=35, pady=4)
        ctk.CTkLabel(prof_frame, text=get_text("profile_label"), font=ctk.CTkFont(size=12, weight="bold")).pack(side="left")

        profiles = vault_storage.list_profiles()
        self.profile_select_menu = ctk.CTkOptionMenu(
            prof_frame,
            values=profiles,
            width=220,
            height=34
        )
        self.profile_select_menu.set(profiles[0] if profiles else "Varsayılan")
        self.profile_select_menu.pack(side="right")

        self.unlock_pass_entry = ctk.CTkEntry(
            frame, placeholder_text=get_text("master_pass_placeholder"), show="*", width=380, height=44, font=ctk.CTkFont(size=14)
        )
        self.unlock_pass_entry.pack(pady=(10, 6))
        self.unlock_pass_entry.bind("<Return>", lambda e: self._handle_unlock_vault())
        self.unlock_pass_entry.focus()

        # Optional 2FA Keyfile Selector on Unlock Screen
        kf_unlock_lbl = ctk.CTkLabel(
            frame,
            text=get_text("keyfile_none_lbl"),
            font=ctk.CTkFont(size=11),
            text_color="#94a3b8"
        )

        def pick_unlock_keyfile():
            fpath = filedialog.askopenfilename(
                title=get_text("keyfile_select_btn"),
                filetypes=[("Kyberon 2FA Keyfile", "*.kkey;*.akey"), ("All Files", "*.*")]
            )
            if fpath:
                self.selected_keyfile_path = fpath
                kf_unlock_lbl.configure(
                    text=get_text("keyfile_selected_lbl", fname=os.path.basename(fpath)),
                    text_color="#4ade80"
                )

        kf_btn = ctk.CTkButton(
            frame,
            text=get_text("keyfile_select_btn"),
            font=ctk.CTkFont(size=11),
            fg_color="#1e293b",
            hover_color="#334155",
            text_color="#38bdf8",
            height=28,
            width=380,
            command=pick_unlock_keyfile
        )
        kf_btn.pack(pady=(2, 2))
        kf_unlock_lbl.pack(pady=(0, 6))

        unlock_btn = ctk.CTkButton(
            frame,
            text=get_text("unlock_btn"),
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            height=44,
            width=380,
            command=self._handle_unlock_vault
        )
        unlock_btn.pack(pady=6)

        # Add New Profile Button
        new_prof_btn = ctk.CTkButton(
            frame,
            text=get_text("btn_new_profile"),
            font=ctk.CTkFont(size=12),
            fg_color="#334155",
            hover_color="#475569",
            text_color="#38bdf8",
            height=32,
            width=380,
            command=self.show_create_profile_screen
        )
        new_prof_btn.pack(pady=(4, 22))

    def _handle_unlock_vault(self):
        prof = self.profile_select_menu.get()
        pwd = self.unlock_pass_entry.get().strip()
        if not pwd:
            return

        try:
            kf_path = getattr(self, "selected_keyfile_path", None)
            data, is_decoy, eff_pwd = vault_storage.unlock_vault(pwd, profile_name=prof, keyfile_path=kf_path)
            self.vault_data = data
            self.master_password = pwd
            self.effective_password = eff_pwd
            self.selected_profile = prof
            self.is_decoy = is_decoy
            self.last_activity_time = time.time()

            # Record identical audit event for both real and decoy vaults to preserve plausible deniability
            military_audit.CryptographicAuditTrail.record_event(
                "VAULT_UNLOCK", prof, "AES-256-GCM Vault session authenticated and unlocked.", "INFO"
            )

            saved_lang = data.get("settings", {}).get("language", i18n.CURRENT_LANG)
            i18n.set_language(saved_lang)

            self.show_dashboard()
        except VaultSecurityError as e:
            military_audit.CryptographicAuditTrail.record_event(
                "AUTH_FAILURE", prof, "Failed authentication attempt (Invalid key or rate-limited).", "WARN"
            )
            messagebox.showerror("Access Denied", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Unlock error: {e}")

    # =========================================================================
    # 2. MAIN DASHBOARD VIEW
    # =========================================================================
    def show_dashboard(self):
        """Constructs main application frame with sidebar navigation and active tab."""
        self.clear_container()
        self.revealed_secrets.clear()

        self.container.grid_columnconfigure(0, weight=0)
        self.container.grid_columnconfigure(1, weight=1)
        self.container.grid_rowconfigure(0, weight=1)

        # Left Sidebar
        sidebar = ctk.CTkFrame(self.container, width=260, corner_radius=0, fg_color="#0f172a")
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)

        logo_lbl = ctk.CTkLabel(
            sidebar,
            text="🛡️ AEGIS VAULT",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#38bdf8"
        )
        logo_lbl.pack(pady=(18, 2), padx=20)

        prof_lbl = ctk.CTkLabel(
            sidebar,
            text=f"👤 {self.selected_profile}",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#94a3b8"
        )
        prof_lbl.pack()

        # Security badge always displays active AES-256-GCM to maintain plausible deniability (duress mode)
        sec_badge = ctk.CTkLabel(
            sidebar, text=get_text("status_active"), font=ctk.CTkFont(size=11, weight="bold"), text_color="#4ade80"
        )
        sec_badge.pack(pady=(2, 10))

        # FIPS 140-3 POST Badge (V-11: Fail-closed default False)
        all_passed = bool(self.post_results.get("all_passed", False)) if isinstance(self.post_results, dict) else False
        fips_color = "#38bdf8" if all_passed else "#ef4444"
        fips_txt = get_text("fips_badge_passed") if all_passed else get_text("fips_badge_failed")
        fips_badge = ctk.CTkLabel(
            sidebar, text=fips_txt, font=ctk.CTkFont(size=10, weight="bold"), text_color=fips_color
        )
        fips_badge.pack(pady=(0, 10))

        # Module Navigation Buttons
        nav_buttons = [
            ("vault", get_text("nav_vault")),
            ("portfolio", get_text("nav_portfolio")),
            ("p2p_chat", get_text("nav_p2p_chat")),
            ("airgap", get_text("nav_airgap")),
            ("shamir", get_text("nav_shamir")),
            ("bip39", get_text("nav_bip39")),
            ("audit", get_text("nav_audit")),
            ("guide", get_text("security_info_title")),
        ]

        self.nav_widgets = {}
        for tab_key, tab_title in nav_buttons:
            is_active = (self.current_tab == tab_key)
            btn = ctk.CTkButton(
                sidebar,
                text=tab_title,
                font=ctk.CTkFont(size=12, weight="bold" if is_active else "normal"),
                fg_color="#0284c7" if is_active else "#1e293b",
                hover_color="#0369a1" if is_active else "#334155",
                height=36,
                command=lambda k=tab_key: self.switch_tab(k)
            )
            btn.pack(pady=4, padx=16, fill="x")
            self.nav_widgets[tab_key] = btn

        # Sidebar Bottom: Update Check, Lock Vault & Timeout Notice
        update_btn = ctk.CTkButton(
            sidebar,
            text=get_text("btn_check_update"),
            font=ctk.CTkFont(size=11),
            fg_color="#334155",
            hover_color="#475569",
            text_color="#38bdf8",
            height=30,
            command=self._check_github_updates_ui
        )
        update_btn.pack(side="bottom", pady=(4, 10), padx=16, fill="x")

        lock_btn = ctk.CTkButton(
            sidebar,
            text=get_text("nav_lock"),
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#dc2626",
            hover_color="#b91c1c",
            height=36,
            command=lambda: self.lock_vault()
        )
        lock_btn.pack(side="bottom", pady=4, padx=16, fill="x")

        info_txt = ctk.CTkLabel(
            sidebar,
            text=get_text("inactivity_notice"),
            font=ctk.CTkFont(size=10),
            text_color="#64748b",
            justify="center"
        )
        info_txt.pack(side="bottom", pady=2)

        panic_lbl = ctk.CTkLabel(
            sidebar,
            text=get_text("panic_hotkey_hint"),
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color="#ef4444",
            justify="center"
        )
        panic_lbl.pack(side="bottom", pady=(0, 4))

        # Right Content Area
        self.main_content = ctk.CTkFrame(self.container, fg_color="#020617")
        self.main_content.grid(row=0, column=1, sticky="nsew")
        self.main_content.grid_rowconfigure(1, weight=1)
        self.main_content.grid_columnconfigure(0, weight=1)

        # Top Bar with Tagline and Language Menu
        top_bar = ctk.CTkFrame(self.main_content, height=60, fg_color="#0b1120", corner_radius=0)
        top_bar.grid(row=0, column=0, sticky="ew")
        top_bar.grid_columnconfigure(0, weight=1)
        top_bar.grid_columnconfigure(1, weight=0)

        app_tagline = ctk.CTkLabel(
            top_bar,
            text=get_text("tagline"),
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#94a3b8"
        )
        app_tagline.grid(row=0, column=0, padx=20, pady=14, sticky="w")

        lang_menu = ctk.CTkOptionMenu(
            top_bar,
            values=["🇹🇷 Türkçe", "🇬🇧 English", "🇷🇺 Русский"],
            width=130,
            height=30,
            font=ctk.CTkFont(size=11),
            command=self.set_language_and_refresh
        )
        cur = i18n.CURRENT_LANG
        lang_menu.set(i18n.LANGUAGES.get(cur, "🇹🇷 Türkçe"))
        lang_menu.grid(row=0, column=1, padx=20, pady=14, sticky="e")

        self.render_active_tab()

    def switch_tab(self, tab_key: str):
        """Switches active navigation tab without destroying background connections."""
        self.current_tab = tab_key
        for k, btn in self.nav_widgets.items():
            is_active = (k == tab_key)
            btn.configure(
                fg_color="#0284c7" if is_active else "#1e293b",
                font=ctk.CTkFont(size=12, weight="bold" if is_active else "normal")
            )
        self.render_active_tab()

    def render_active_tab(self):
        """Renders the content view for the currently selected tab."""
        for widget in self.main_content.grid_slaves(row=1, column=0):
            widget.destroy()

        tab_container = ctk.CTkFrame(self.main_content, fg_color="transparent")
        tab_container.grid(row=1, column=0, sticky="nsew", padx=20, pady=15)
        tab_container.grid_columnconfigure(0, weight=1)
        tab_container.grid_rowconfigure(0, weight=1)

        if self.current_tab == "vault":
            self._render_vault_view(tab_container)
        elif self.current_tab == "portfolio":
            self._render_portfolio_view(tab_container)
        elif self.current_tab == "p2p_chat":
            self._render_p2p_chat_view(tab_container)
        elif self.current_tab == "airgap":
            self._render_airgap_view(tab_container)
        elif self.current_tab == "shamir":
            self._render_shamir_view(tab_container)
        elif self.current_tab == "bip39":
            self._render_bip39_view(tab_container)
        elif self.current_tab == "audit":
            self._render_audit_view(tab_container)
        elif self.current_tab == "guide":
            self._render_guide_view(tab_container)

    def lock_vault(self, reason=None):
        """Locks the vault, terminates live chat session, scrubs clipboard & RAM state, and returns to unlock screen."""
        if not self.master_password and not self.vault_data:
            return

        if hasattr(self, "p2p_session") and self.p2p_session:
            try:
                self.p2p_session.close()
            except Exception:
                pass
            self.p2p_session = None

        try:
            self.clipboard_clear()
        except Exception:
            pass

        military_audit.CryptographicAuditTrail.record_event(
            "VAULT_LOCK",
            self.selected_profile or "System",
            f"Vault session locked and session keys zeroized ({reason or 'Manual Lock'}).",
            "INFO"
        )

        self.p2p_message_history.clear()
        self.master_password = None
        self.effective_password = None
        self.vault_data = None
        self.is_decoy = False
        self.revealed_secrets.clear()
        self.clear_container()
        self.show_unlock_screen()
        if reason:
            messagebox.showinfo("Vault Locked", reason)

    def _check_github_updates_ui(self):
        """Asynchronously queries GitHub Releases API without blocking the GUI thread."""
        def worker():
            has_up, latest_ver, down_url, notes = updater.check_for_github_update()
            pinned_sha256 = updater.get_pinned_release_sha256(down_url) if down_url else None

            def show_dialog():
                if has_up:
                    if not pinned_sha256:
                        messagebox.showerror(
                            "Update Rejected (V-10 Supply-Chain Shield)",
                            f"Kyberon v{latest_ver} was found, but its release metadata does not include a pinned 64-hex SHA-256 digest.\nUnsigned/unverified binary execution blocked."
                        )
                        return
                    if messagebox.askyesno("Update Available", f"Kyberon v{latest_ver} is available!\nSHA-256: {pinned_sha256[:16]}...\n\n{notes}\n\nDownload and install verified binary now?"):
                        threading.Thread(
                            target=lambda: updater.apply_executable_update(down_url, expected_sha256=pinned_sha256),
                            daemon=True
                        ).start()
                        messagebox.showinfo("Downloading", "Verified update is downloading, application will restart automatically.")
                else:
                    if messagebox.askyesno("Update Status", f"{notes}\n\nGitHub Releases sayfasını tarayıcıda açmak ister misiniz?"):
                        updater.open_github_releases_page()

            self.after(0, show_dialog)

        threading.Thread(target=worker, daemon=True).start()

    # =========================================================================
    # 3. VAULT VIEW & ENCRYPTED FILE LOCKER
    # =========================================================================
    def _render_vault_view(self, parent):
        parent.grid_rowconfigure(1, weight=1)

        top_controls = ctk.CTkFrame(parent, fg_color="transparent")
        top_controls.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        top_controls.grid_columnconfigure(0, weight=1)
        top_controls.grid_columnconfigure(1, weight=0)

        self.search_entry = ctk.CTkEntry(
            top_controls, placeholder_text=get_text("search_placeholder"), width=360, height=36
        )
        self.search_entry.grid(row=0, column=0, sticky="w")
        self.search_entry.bind("<KeyRelease>", lambda e: self._render_vault_cards())

        btn_grp = ctk.CTkFrame(top_controls, fg_color="transparent")
        btn_grp.grid(row=0, column=1, sticky="e")

        backup_btn = ctk.CTkButton(
            btn_grp,
            text=get_text("btn_backup_vault"),
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#334155",
            hover_color="#475569",
            height=36,
            command=self._backup_vault_to_file
        )
        backup_btn.pack(side="left", padx=4)

        restore_btn = ctk.CTkButton(
            btn_grp,
            text=get_text("btn_restore_vault"),
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#334155",
            hover_color="#475569",
            height=36,
            command=self._restore_vault_from_file
        )
        restore_btn.pack(side="left", padx=4)

        add_file_btn = ctk.CTkButton(
            btn_grp,
            text=get_text("btn_add_file"),
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#10b981",
            hover_color="#059669",
            height=36,
            command=self.open_add_file_modal
        )
        add_file_btn.pack(side="left", padx=4)

        add_btn = ctk.CTkButton(
            btn_grp,
            text=get_text("btn_add_secret"),
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            height=36,
            command=self.open_add_secret_modal
        )
        add_btn.pack(side="left", padx=4)

        self.vault_cards_frame = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        self.vault_cards_frame.grid(row=1, column=0, sticky="nsew")
        self.vault_cards_frame.grid_columnconfigure(0, weight=1)

        self._render_vault_cards()

    def _render_vault_cards(self):
        for w in self.vault_cards_frame.winfo_children():
            w.destroy()

        query = self.search_entry.get().strip().lower() if hasattr(self, "search_entry") else ""
        items = self.vault_data.get("items", [])
        filtered = [
            i for i in items
            if query in i["title"].lower() or query in i.get("category", "").lower()
        ]

        if not filtered:
            lbl = ctk.CTkLabel(
                self.vault_cards_frame,
                text=get_text("empty_vault_msg"),
                font=ctk.CTkFont(size=13),
                text_color="#64748b",
                justify="center"
            )
            lbl.pack(pady=70)
            return

        for item in filtered:
            self._create_vault_card(item)

    def _create_vault_card(self, item: dict):
        item_id = item["id"]
        is_revealed = item_id in self.revealed_secrets
        is_file = item.get("is_file", False)

        card = ctk.CTkFrame(self.vault_cards_frame, corner_radius=10, fg_color="#111827", border_width=1, border_color="#1f2937")
        card.pack(fill="x", pady=5, padx=3)
        card.grid_columnconfigure(1, weight=1)

        category = item.get("category", "General")
        cat_color = {
            "Bitcoin / Kripto Seed": "#f59e0b",
            "Özel Anahtar (Private Key)": "#ef4444",
            "Kullanıcı Parolası": "#3b82f6",
            "Gizli Not": "#10b981",
            "Şifreli Dosya / Belge": "#10b981",
            "Bitcoin / Crypto Seed": "#f59e0b",
            "Private Key": "#ef4444",
            "User Password": "#3b82f6",
            "Secret Note": "#10b981",
            "Encrypted File / Document": "#10b981"
        }.get(category, "#8b5cf6")

        title_box = ctk.CTkFrame(card, fg_color="transparent")
        title_box.grid(row=0, column=0, padx=14, pady=10, sticky="w")
        lbl_title = ctk.CTkLabel(title_box, text=item["title"], font=ctk.CTkFont(size=14, weight="bold"), text_color="#f8fafc")
        lbl_title.pack(anchor="w")

        cat_badge = ctk.CTkLabel(title_box, text=f"● {category}", font=ctk.CTkFont(size=11, weight="bold"), text_color=cat_color)
        cat_badge.pack(anchor="w")

        secret_box = ctk.CTkFrame(card, fg_color="#1e293b", corner_radius=8)
        secret_box.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        if is_file:
            display_text = get_text("vault_file_display", fname=item.get('file_name'), size=item.get('file_size', 0))
            lbl_secret = ctk.CTkLabel(
                secret_box,
                text=display_text,
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                text_color="#4ade80"
            )
            lbl_secret.pack(side="left", padx=12, pady=6)
        else:
            display_text = item["secret"] if is_revealed else "•" * 24
            lbl_secret = ctk.CTkLabel(
                secret_box,
                text=display_text,
                font=ctk.CTkFont(family="Consolas", size=13),
                text_color="#38bdf8" if is_revealed else "#94a3b8"
            )
            lbl_secret.pack(side="left", padx=12, pady=6)

        btn_box = ctk.CTkFrame(card, fg_color="transparent")
        btn_box.grid(row=0, column=2, padx=14, pady=10, sticky="e")

        if is_file:
            export_btn = ctk.CTkButton(
                btn_box,
                text=get_text("btn_export_file"),
                font=ctk.CTkFont(size=11, weight="bold"),
                width=135,
                height=30,
                fg_color="#059669",
                hover_color="#047857",
                command=lambda i=item: self._export_file_item(i)
            )
            export_btn.pack(side="left", padx=3)
        else:
            eye_btn = ctk.CTkButton(
                btn_box,
                text=get_text("btn_hide") if is_revealed else get_text("btn_show"),
                width=70,
                height=30,
                fg_color="#334155",
                hover_color="#475569",
                command=lambda i=item_id: self._toggle_reveal_secret(i)
            )
            eye_btn.pack(side="left", padx=3)

            copy_btn = ctk.CTkButton(
                btn_box,
                text=get_text("btn_copy"),
                width=36,
                height=30,
                fg_color="#0284c7",
                hover_color="#0369a1",
                command=lambda s=item["secret"]: self._copy_to_clipboard(s)
            )
            copy_btn.pack(side="left", padx=3)

        del_btn = ctk.CTkButton(
            btn_box,
            text="🗑️",
            width=36,
            height=30,
            fg_color="#450a0a",
            hover_color="#7f1d1d",
            text_color="#f87171",
            command=lambda i=item_id, t=item["title"]: self._delete_secret(i, t)
        )
        del_btn.pack(side="left", padx=3)

    def open_add_file_modal(self):
        fpath = filedialog.askopenfilename(
            title=get_text("vault_file_dialog_title"),
            filetypes=[("All Files", "*.*")]
        )
        if not fpath:
            return

        fsize = os.path.getsize(fpath)
        if fsize > 15 * 1024 * 1024:
            messagebox.showerror("Error", get_text("vault_file_oversize_err"))
            return

        fname = os.path.basename(fpath)
        with open(fpath, "rb") as f:
            file_bytes = f.read()

        vault_storage.add_file_item(
            self.effective_password or self.master_password,
            self.vault_data,
            title=fname,
            file_name=fname,
            file_bytes=file_bytes,
            notes=get_text("vault_file_notes_orig", path=fpath)
        )
        self._render_vault_cards()
        messagebox.showinfo("Success", get_text("vault_file_added_success", fname=fname))

    def _export_file_item(self, item: dict):
        fname = item.get("file_name", "file.bin")
        dest = filedialog.asksaveasfilename(
            initialfile=fname,
            title=get_text("vault_file_export_title")
        )
        if not dest:
            return
        try:
            raw_b = base64.b64decode(item["file_b64"])
            with open(dest, "wb") as f:
                f.write(raw_b)
            messagebox.showinfo("Success", get_text("vault_file_exported_success", fname=fname, dest=dest))
        except Exception as e:
            messagebox.showerror("Error", get_text("vault_file_export_err", err=str(e)))

    def _backup_vault_to_file(self):
        """Exports the active encrypted vault file to a user-selected backup location."""
        v_file, d_file = vault_storage.get_profile_files(self.selected_profile)
        source_file = d_file if self.is_decoy else v_file
        if not os.path.exists(source_file):
            messagebox.showerror("Error", "Vault file does not exist on disk!")
            return

        default_name = f"Kyberon_Backup_{self.selected_profile}_{time.strftime('%Y%m%d_%H%M%S')}.mvat"
        dest = filedialog.asksaveasfilename(
            initialfile=default_name,
            defaultextension=".mvat",
            filetypes=[("Kyberon Vault Backup", "*.mvat"), ("All Files", "*.*")],
            title=get_text("vault_backup_title")
        )
        if not dest:
            return

        try:
            with open(source_file, "rb") as f_src:
                raw_data = f_src.read()
            with open(dest, "wb") as f_dst:
                f_dst.write(raw_data)
            messagebox.showinfo("Success", get_text("vault_backup_success", dest=dest))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to backup vault: {e}")

    def _restore_vault_from_file(self):
        """Restores or imports a vault profile from a user-selected .mvat backup."""
        fpath = filedialog.askopenfilename(
            title=get_text("vault_restore_title"),
            filetypes=[("Kyberon Vault Backup", "*.mvat"), ("All Files", "*.*")]
        )
        if not fpath:
            return

        try:
            with open(fpath, "r", encoding="utf-8") as f:
                armored = f.read()

            can_decrypt_with_current = False
            decrypted_data = None
            try:
                raw_b = vault_storage.MilitaryVault.decrypt(armored, self.effective_password or self.master_password)
                decrypted_data = json.loads(raw_b.decode("utf-8"))
                can_decrypt_with_current = True
            except Exception:
                can_decrypt_with_current = False

            base_name = os.path.splitext(os.path.basename(fpath))[0]
            clean_name = base_name.replace("Kyberon_Backup_", "").replace("Kyberon_", "").replace("Kyberon_Backup_", "").replace("Kyberon_", "")

            if can_decrypt_with_current:
                v_file, d_file = vault_storage.get_profile_files(self.selected_profile)
                target_file = d_file if self.is_decoy else v_file
                with open(target_file, "w", encoding="utf-8") as f_out:
                    f_out.write(armored)
                self.vault_data = decrypted_data
                self._render_vault_cards()
                messagebox.showinfo("Success", get_text("vault_restore_success", profile=self.selected_profile))
            else:
                vault_storage.ensure_profiles_dir()
                import_name = f"Import_{clean_name}"[:24]
                dest_file = os.path.join(vault_storage.PROFILES_DIR, f"{import_name}.mvat")
                with open(dest_file, "w", encoding="utf-8") as f_out:
                    f_out.write(armored)
                messagebox.showinfo("Success", get_text("vault_restore_success", profile=import_name))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to restore vault backup: {e}")

    def _toggle_reveal_secret(self, item_id: str):
        if item_id in self.revealed_secrets:
            self.revealed_secrets.remove(item_id)
        else:
            self.revealed_secrets.add(item_id)
        self._render_vault_cards()

    def _copy_to_clipboard(self, text: str):
        """Copies secret to clipboard and schedules automatic zeroization after 30 seconds."""
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo(
            get_text("copied_alert"),
            f"{text[:40]}{'...' if len(text) > 40 else ''}\n\n⏱️ [Auto-Zeroize: Clipboard will clear in 30s]"
        )

        def auto_scrub_clipboard(expected_val=text):
            try:
                current = self.clipboard_get()
                if current == expected_val:
                    self.clipboard_clear()
            except Exception:
                pass

        self.after(30000, auto_scrub_clipboard)

    def _delete_secret(self, item_id: str, title: str):
        msg = get_text("delete_confirm", title=title)
        if messagebox.askyesno("Confirm", msg):
            vault_storage.delete_secret_item(self.effective_password or self.master_password, self.vault_data, item_id)
            if item_id in self.revealed_secrets:
                self.revealed_secrets.remove(item_id)
            self._render_vault_cards()

    def open_add_secret_modal(self):
        modal = ctk.CTkToplevel(self)
        modal.title(get_text("modal_add_title"))
        modal.geometry("560x520")
        modal.transient(self)
        modal.grab_set()

        lbl_head = ctk.CTkLabel(modal, text=get_text("modal_add_title"), font=ctk.CTkFont(size=18, weight="bold"), text_color="#38bdf8")
        lbl_head.pack(pady=(16, 6), padx=25)

        title_entry = ctk.CTkEntry(modal, placeholder_text=get_text("field_title"), height=38)
        title_entry.pack(pady=6, padx=25, fill="x")

        cat_menu = ctk.CTkOptionMenu(
            modal,
            values=[get_text("cat_seed"), get_text("cat_privkey"), get_text("cat_pass"), get_text("cat_note")],
            height=36
        )
        cat_menu.pack(pady=6, padx=25, fill="x")

        lbl_sec = ctk.CTkLabel(modal, text=get_text("field_secret"), font=ctk.CTkFont(size=12, weight="bold"))
        lbl_sec.pack(anchor="w", padx=25, pady=(8, 2))

        secret_text = ctk.CTkTextbox(modal, height=90, font=ctk.CTkFont(family="Consolas", size=13))
        secret_text.pack(pady=4, padx=25, fill="x")

        ent_lbl = ctk.CTkLabel(modal, text="Entropy: 0 bits", font=ctk.CTkFont(size=11), text_color="#94a3b8")
        ent_lbl.pack(anchor="w", padx=25)

        def update_entropy_display(event=None):
            val = secret_text.get("1.0", "end").strip()
            res = crypto_utils.calculate_password_entropy(val)
            ent_lbl.configure(text=f"Entropy: {res['entropy']} bits - {res['label']}", text_color=res["color"])

        secret_text.bind("<KeyRelease>", update_entropy_display)

        def generate_and_fill():
            pw = vault_storage.generate_secure_password(length=32, use_symbols=True)
            secret_text.delete("1.0", "end")
            secret_text.insert("1.0", pw)
            update_entropy_display()

        gen_btn = ctk.CTkButton(
            modal,
            text=get_text("btn_generate_pass"),
            fg_color="#1e293b",
            hover_color="#334155",
            text_color="#38bdf8",
            height=32,
            command=generate_and_fill
        )
        gen_btn.pack(pady=6, padx=25, fill="x")

        notes_entry = ctk.CTkEntry(modal, placeholder_text=get_text("field_notes"), height=36)
        notes_entry.pack(pady=6, padx=25, fill="x")

        def save_and_close():
            t = title_entry.get().strip()
            s = secret_text.get("1.0", "end").strip()
            c = cat_menu.get()
            n = notes_entry.get().strip()

            if not t or not s:
                return

            vault_storage.add_secret_item(
                self.effective_password or self.master_password, self.vault_data, title=t, category=c, secret_value=s, notes=n
            )
            modal.destroy()
            self._render_vault_cards()

        save_btn = ctk.CTkButton(
            modal,
            text=get_text("btn_save_vault"),
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            height=40,
            command=save_and_close
        )
        save_btn.pack(pady=(12, 18), padx=25, fill="x")

    # =========================================================================
    # 4. PORTFOLIO VIEW (BLOCKCHAIN.INFO VERIFIED)
    # =========================================================================
    def _render_portfolio_view(self, parent):
        parent.grid_rowconfigure(2, weight=1)

        info_card = ctk.CTkFrame(parent, fg_color="#172554", border_width=1, border_color="#1d4ed8", corner_radius=10)
        info_card.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        info_lbl = ctk.CTkLabel(info_card, text=get_text("portfolio_desc"), font=ctk.CTkFont(size=12), text_color="#93c5fd", justify="left")
        info_lbl.pack(padx=16, pady=10, anchor="w")

        stats_frame = ctk.CTkFrame(parent, fg_color="#0f172a", corner_radius=10)
        stats_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        stats_frame.grid_columnconfigure(0, weight=1)
        stats_frame.grid_columnconfigure(1, weight=1)

        portfolio_items = self.vault_data.get("portfolio", [])
        totals = crypto_portfolio.calculate_portfolio_value(portfolio_items, self.live_prices)

        total_box = ctk.CTkFrame(stats_frame, fg_color="transparent")
        total_box.grid(row=0, column=0, padx=20, pady=12, sticky="w")
        ctk.CTkLabel(total_box, text=get_text("total_portfolio_val"), font=ctk.CTkFont(size=12), text_color="#94a3b8").pack(anchor="w")
        ctk.CTkLabel(
            total_box,
            text=f"${totals['total_usd']:,.2f}  |  ₺{totals['total_try']:,.2f}",
            font=ctk.CTkFont(size=19, weight="bold"),
            text_color="#4ade80"
        ).pack(anchor="w")

        price_box = ctk.CTkFrame(stats_frame, fg_color="transparent")
        price_box.grid(row=0, column=1, padx=20, pady=12, sticky="e")
        btc_p = self.live_prices.get("BTC", {}).get("usd", 0)
        eth_p = self.live_prices.get("ETH", {}).get("usd", 0)
        sol_p = self.live_prices.get("SOL", {}).get("usd", 0)
        price_str = f"BTC: ${btc_p:,.0f} | ETH: ${eth_p:,.0f} | SOL: ${sol_p:,.1f}"
        ctk.CTkLabel(price_box, text=get_text("crypto_price_live"), font=ctk.CTkFont(size=11), text_color="#94a3b8").pack(anchor="e")
        ctk.CTkLabel(price_box, text=price_str, font=ctk.CTkFont(size=13, weight="bold"), text_color="#38bdf8").pack(anchor="e")

        addr_scroll = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        addr_scroll.grid(row=2, column=0, sticky="nsew")
        addr_scroll.grid_columnconfigure(0, weight=1)

        top_act = ctk.CTkFrame(addr_scroll, fg_color="transparent")
        top_act.pack(fill="x", pady=(0, 8))
        add_addr_btn = ctk.CTkButton(top_act, text=get_text("btn_add_address"), fg_color="#0284c7", command=self._open_add_address_modal, height=32)
        add_addr_btn.pack(side="left")

        ref_btn = ctk.CTkButton(top_act, text=get_text("btn_refresh_prices"), fg_color="#334155", command=self._refresh_portfolio_and_balances, height=32)
        ref_btn.pack(side="right")

        if not portfolio_items:
            ctk.CTkLabel(addr_scroll, text=get_text("portfolio_empty"), font=ctk.CTkFont(size=13), text_color="#64748b").pack(pady=40)
        else:
            for item in portfolio_items:
                self._create_address_card(addr_scroll, item)

    def _create_address_card(self, parent, item: dict):
        coin = item.get("coin", "BTC")
        amount = float(item.get("amount", 0.0))
        usd_rate = self.live_prices.get(coin, {}).get("usd", 0.0)
        val_usd = amount * usd_rate

        card = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=10, border_width=1, border_color="#1f2937")
        card.pack(fill="x", pady=4)
        card.grid_columnconfigure(1, weight=1)

        col_left = ctk.CTkFrame(card, fg_color="transparent")
        col_left.grid(row=0, column=0, padx=14, pady=10, sticky="w")
        ctk.CTkLabel(col_left, text=item.get("label", "Cold Wallet"), font=ctk.CTkFont(size=14, weight="bold"), text_color="#f8fafc").pack(anchor="w")
        ctk.CTkLabel(col_left, text=f"{coin}: {item.get('address')[:16]}...{item.get('address')[-8:]}", font=ctk.CTkFont(family="Consolas", size=11), text_color="#94a3b8").pack(anchor="w")

        col_mid = ctk.CTkFrame(card, fg_color="transparent")
        col_mid.grid(row=0, column=1, padx=10, pady=10, sticky="e")
        ctk.CTkLabel(col_mid, text=f"{amount} {coin}", font=ctk.CTkFont(size=14, weight="bold"), text_color="#38bdf8").pack(anchor="e")
        ctk.CTkLabel(col_mid, text=f"≈ ${val_usd:,.2f}", font=ctk.CTkFont(size=12), text_color="#4ade80").pack(anchor="e")

        del_btn = ctk.CTkButton(
            card,
            text="🗑️",
            width=36,
            height=30,
            fg_color="#450a0a",
            hover_color="#7f1d1d",
            text_color="#f87171",
            command=lambda i=item["id"]: self._delete_portfolio_item(i)
        )
        del_btn.grid(row=0, column=2, padx=14, pady=10)

    def _open_add_address_modal(self):
        modal = ctk.CTkToplevel(self)
        modal.title(get_text("btn_add_address"))
        modal.geometry("520x440")
        modal.transient(self)
        modal.grab_set()

        lbl = ctk.CTkLabel(modal, text=get_text("btn_add_address"), font=ctk.CTkFont(size=16, weight="bold"), text_color="#38bdf8")
        lbl.pack(pady=(16, 8))

        label_in = ctk.CTkEntry(modal, placeholder_text=get_text("portfolio_lbl_ph"), height=36)
        label_in.pack(pady=5, padx=25, fill="x")

        coin_menu = ctk.CTkOptionMenu(modal, values=["BTC", "ETH", "SOL"], height=36)
        coin_menu.pack(pady=5, padx=25, fill="x")

        addr_in = ctk.CTkEntry(modal, placeholder_text=get_text("portfolio_addr_ph"), height=36)
        addr_in.pack(pady=5, padx=25, fill="x")

        val_status_lbl = ctk.CTkLabel(modal, text="", font=ctk.CTkFont(size=11), text_color="#94a3b8")
        val_status_lbl.pack(padx=25, anchor="w")

        amount_in = ctk.CTkEntry(modal, placeholder_text=get_text("portfolio_amt_ph"), height=36)
        amount_in.pack(pady=5, padx=25, fill="x")

        def check_and_fetch_live():
            c = coin_menu.get()
            a = addr_in.get().strip()
            is_valid, msg = crypto_portfolio.validate_crypto_address(c, a)
            if not is_valid:
                val_status_lbl.configure(text=f"❌ {msg}", text_color="#ef4444")
                return
            val_status_lbl.configure(text=f"✅ {msg}", text_color="#4ade80")

            if c == "BTC":
                live_btc = crypto_portfolio.fetch_live_btc_balance(a)
                amount_in.delete(0, "end")
                amount_in.insert(0, str(live_btc))
                messagebox.showinfo("Blockchain.info", f"Live on-chain balance fetched: {live_btc} BTC")

        fetch_btn = ctk.CTkButton(
            modal,
            text=get_text("portfolio_btn_fetch"),
            fg_color="#1e293b",
            hover_color="#334155",
            text_color="#38bdf8",
            height=32,
            command=check_and_fetch_live
        )
        fetch_btn.pack(pady=6, padx=25, fill="x")

        def save():
            l = label_in.get().strip()
            c = coin_menu.get()
            a = addr_in.get().strip()
            is_valid, msg = crypto_portfolio.validate_crypto_address(c, a)
            if not is_valid:
                messagebox.showerror("Error", f"Invalid address: {msg}")
                return
            try:
                amt = float(amount_in.get().strip())
            except ValueError:
                amt = 0.0

            vault_storage.add_portfolio_item(self.effective_password or self.master_password, self.vault_data, coin=c, label=l, address=a, amount=amt)
            modal.destroy()
            self.render_active_tab()

        save_btn = ctk.CTkButton(modal, text=get_text("btn_save"), fg_color="#0284c7", height=40, command=save)
        save_btn.pack(pady=12, padx=25, fill="x")

    def _delete_portfolio_item(self, item_id: str):
        vault_storage.delete_portfolio_item(self.effective_password or self.master_password, self.vault_data, item_id)
        self.render_active_tab()

    def _refresh_portfolio_and_balances(self):
        """Asynchronously refreshes live market prices and on-chain BTC balances without freezing GUI."""
        def worker():
            prices = crypto_portfolio.fetch_live_prices()
            self.live_prices = prices
            if self.vault_data:
                for item in self.vault_data.get("portfolio", []):
                    if item.get("coin") == "BTC":
                        live_b = crypto_portfolio.fetch_live_btc_balance(item.get("address", ""))
                        if live_b > 0:
                            item["amount"] = live_b
                if self.master_password:
                    vault_storage.save_vault(self.effective_password or self.master_password, self.vault_data, is_decoy=self.is_decoy)

            def on_done():
                if self.master_password:
                    self.render_active_tab()
                    messagebox.showinfo("Updated", get_text("portfolio_refreshed_alert"))

            self.after(0, on_done)

        threading.Thread(target=worker, daemon=True).start()

    # =========================================================================
    # 5. PERSISTENT LIVE P2P ENCRYPTED CHAT (SURVIVES TAB SWITCHES)
    # =========================================================================
    def _on_p2p_msg_received(self, sender: str, text: str, ts: str, is_mine: bool):
        """Global callback when a message arrives via MQTT relay."""
        record = {
            "sender": sender,
            "text": text,
            "ts": ts,
            "is_mine": is_mine,
            "time_recv": time.time(),
            "burn": text.startswith("[BURNT-30]:"),
            "file": text.startswith("[FILE-DROP]:")
        }
        self.p2p_message_history.append(record)

        # If chat tab is active and visible, render bubble immediately
        if self.current_tab == "p2p_chat" and hasattr(self, "p2p_messages_box") and self.p2p_messages_box.winfo_exists():
            self.after(0, lambda r=record: self._render_single_p2p_bubble(r))

    def _on_p2p_status_update(self, text: str):
        """Global callback when P2P connection status updates."""
        self.p2p_status_text = text
        if self.current_tab == "p2p_chat":
            if hasattr(self, "p2p_status_lbl") and self.p2p_status_lbl.winfo_exists():
                self.after(0, lambda: self.p2p_status_lbl.configure(text=text))
            if hasattr(self, "p2p_conn_btn") and self.p2p_conn_btn.winfo_exists():
                is_conn = bool(self.p2p_session and self.p2p_session.is_connected)
                btn_txt = get_text("btn_chat_disconnect") if is_conn else get_text("btn_chat_connect")
                btn_fg = "#dc2626" if is_conn else "#059669"
                btn_hov = "#b91c1c" if is_conn else "#047857"
                self.after(0, lambda: self.p2p_conn_btn.configure(text=btn_txt, fg_color=btn_fg, hover_color=btn_hov))

    def _render_single_p2p_bubble(self, record: dict):
        """Renders an individual chat bubble into the active messages box."""
        if not hasattr(self, "p2p_messages_box") or not self.p2p_messages_box.winfo_exists():
            return

        sender = record["sender"]
        text = record["text"]
        ts = record["ts"]
        is_mine = record["is_mine"]
        time_recv = record.get("time_recv", time.time())
        is_burn = record.get("burn", False)
        is_file = record.get("file", False)

        # Handle file drop packet
        if is_file:
            try:
                f_json = json.loads(text[len("[FILE-DROP]:"):].strip())
                raw_fname = str(f_json.get("filename", "file.bin"))
                fname = os.path.basename(raw_fname).replace("\x00", "").strip() or "file.bin"
                fsize = int(f_json.get("size", 0))
                b64_content = f_json.get("data", "")
            except Exception:
                fname = "file.bin"
                fsize = 0
                b64_content = ""

            bubble = ctk.CTkFrame(
                self.p2p_messages_box,
                fg_color="#064e3b" if is_mine else "#14532d",
                border_width=1,
                border_color="#22c55e",
                corner_radius=8
            )
            bubble.pack(fill="x", pady=4, padx=8)

            hdr = get_text("chat_file_tx_hdr", ts=ts) if is_mine else get_text("chat_file_rx_hdr", sender=sender, ts=ts)
            ctk.CTkLabel(bubble, text=hdr, font=ctk.CTkFont(size=10, weight="bold"), text_color="#86efac").pack(anchor="w", padx=10, pady=(4, 0))
            badge_txt = get_text("chat_file_badge", fname=fname, size=fsize)
            ctk.CTkLabel(bubble, text=badge_txt, font=ctk.CTkFont(size=13, weight="bold"), text_color="#ffffff").pack(anchor="w", padx=10, pady=(2, 4))

            def save_dropped_file():
                dest = filedialog.asksaveasfilename(initialfile=fname, title=get_text("vault_file_export_title"))
                if not dest:
                    return
                try:
                    with open(dest, "wb") as f:
                        f.write(base64.b64decode(b64_content))
                    messagebox.showinfo("Success", get_text("chat_file_saved_msg", dest=dest))
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save file: {e}")

            dl_btn = ctk.CTkButton(
                bubble,
                text=get_text("chat_file_dl_btn", fname=fname),
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color="#16a34a",
                hover_color="#15803d",
                height=28,
                command=save_dropped_file
            )
            dl_btn.pack(anchor="w", padx=10, pady=(2, 8))
            return

        # Handle text or 30-second self-destruct message
        display_text = text[len("[BURNT-30]:"):].strip() if is_burn else text

        bubble = ctk.CTkFrame(
            self.p2p_messages_box,
            fg_color="#0284c7" if is_mine else "#1e293b",
            border_width=1 if is_burn else 0,
            border_color="#ef4444" if is_burn else "#334155",
            corner_radius=8
        )
        bubble.pack(fill="x", pady=4, padx=8)

        hdr = f"{get_text('chat_you')} ({ts})" if is_mine else f"{sender} ({ts})"
        if is_burn:
            hdr += get_text("chat_burn_badge")

        ctk.CTkLabel(bubble, text=hdr, font=ctk.CTkFont(size=10, weight="bold"), text_color="#fca5a5" if is_burn else "#cbd5e1").pack(anchor="w", padx=10, pady=(4, 0))
        ctk.CTkLabel(bubble, text=display_text, font=ctk.CTkFont(size=13), text_color="#ffffff", justify="left").pack(anchor="w", padx=10, pady=(2, 6))

        if is_burn:
            elapsed = time.time() - time_recv
            remaining_ms = max(100, int((30 - elapsed) * 1000))
            self.after(remaining_ms, lambda b=bubble, r=record: self._expire_burnt_msg(b, r))

    def _expire_burnt_msg(self, bubble, record):
        """Destroys an expired self-destruct message bubble and removes it from history."""
        try:
            if bubble and bubble.winfo_exists():
                bubble.destroy()
        except Exception:
            pass
        if record in self.p2p_message_history:
            self.p2p_message_history.remove(record)

    def _render_p2p_chat_view(self, parent):
        """Constructs live P2P chat interface while maintaining persistent connection and history."""
        parent.grid_rowconfigure(1, weight=1)

        info_card = ctk.CTkFrame(parent, fg_color="#1e1b4b", border_width=1, border_color="#3730a3", corner_radius=10)
        info_card.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        info_lbl = ctk.CTkLabel(info_card, text=get_text("p2p_chat_desc"), font=ctk.CTkFont(size=12), text_color="#c7d2fe", justify="left", wraplength=820)
        info_lbl.pack(padx=16, pady=10, anchor="w")

        chat_layout = ctk.CTkFrame(parent, fg_color="transparent")
        chat_layout.grid(row=1, column=0, sticky="nsew")
        chat_layout.grid_rowconfigure(1, weight=1)
        chat_layout.grid_columnconfigure(0, weight=1)

        # Connection Controls
        top_conn = ctk.CTkFrame(chat_layout, fg_color="#0f172a", corner_radius=10)
        top_conn.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        # Status Label
        is_conn = (self.p2p_session is not None and self.p2p_session.is_connected)
        default_status = get_text("chat_status_connected", room=self.p2p_saved_room) if is_conn else get_text("chat_status_disconnected")
        self.p2p_status_lbl = ctk.CTkLabel(
            top_conn,
            text=self.p2p_status_text or default_status,
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#4ade80" if is_conn else "#94a3b8"
        )
        self.p2p_status_lbl.pack(padx=15, pady=(10, 4), anchor="w")

        ctrl_row1 = ctk.CTkFrame(top_conn, fg_color="transparent")
        ctrl_row1.pack(fill="x", padx=15, pady=(2, 4))

        nick_in = ctk.CTkEntry(ctrl_row1, placeholder_text=get_text("chat_nick"), width=120, height=32)
        nick_in.insert(0, self.p2p_saved_nick or self.selected_profile)
        nick_in.pack(side="left", padx=3)

        room_in = ctk.CTkEntry(ctrl_row1, placeholder_text=get_text("chat_room_name"), width=160, height=32)
        room_in.insert(0, self.p2p_saved_room)
        room_in.pack(side="left", padx=3)

        room_key_in = ctk.CTkEntry(ctrl_row1, placeholder_text=get_text("chat_room_key"), show="*", width=160, height=32)
        room_key_in.insert(0, self.p2p_saved_key)
        room_key_in.pack(side="left", padx=3)

        def sync_inputs(e=None):
            self.p2p_saved_nick = nick_in.get().strip()
            self.p2p_saved_room = room_in.get().strip()
            self.p2p_saved_key = room_key_in.get().strip()

        nick_in.bind("<KeyRelease>", sync_inputs)
        room_in.bind("<KeyRelease>", sync_inputs)
        room_key_in.bind("<KeyRelease>", sync_inputs)

        # Connection Toggle Handler
        def toggle_connect():
            if self.p2p_session and self.p2p_session.is_connected:
                self.p2p_session.close()
                self.p2p_session = None
                self.p2p_status_text = get_text("chat_status_left")
                conn_btn.configure(text=get_text("btn_chat_connect"), fg_color="#059669", hover_color="#047857")
                self.p2p_status_lbl.configure(text=self.p2p_status_text, text_color="#94a3b8")
            else:
                sync_inputs()
                nick = self.p2p_saved_nick or "Anonymous"
                room = self.p2p_saved_room or "general-room"
                key = self.p2p_saved_key
                if not key:
                    messagebox.showerror("Error", "Please enter a room key!")
                    return
                if self.p2p_session:
                    self.p2p_session.close()

                self.p2p_session = live_p2p_chat.GlobalEncryptedChatSession(
                    nick, room, key, self._on_p2p_msg_received, self._on_p2p_status_update
                )
                self.p2p_session.connect()
                conn_btn.configure(text=get_text("btn_chat_disconnect"), fg_color="#dc2626", hover_color="#b91c1c")

        btn_txt = get_text("btn_chat_disconnect") if is_conn else get_text("btn_chat_connect")
        btn_fg = "#dc2626" if is_conn else "#059669"
        btn_hov = "#b91c1c" if is_conn else "#047857"
        conn_btn = ctk.CTkButton(ctrl_row1, text=btn_txt, fg_color=btn_fg, hover_color=btn_hov, width=180, height=32, command=toggle_connect)
        conn_btn.pack(side="left", padx=6)
        self.p2p_conn_btn = conn_btn

        # Re-attach live session callbacks to current window
        if self.p2p_session:
            self.p2p_session.on_message = self._on_p2p_msg_received
            self.p2p_session.on_status = self._on_p2p_status_update

        # Row 2: Random Tactical Room Generator, Copy Invite, PQ-KEM Handshake, and Zeroize
        ctrl_row2 = ctk.CTkFrame(top_conn, fg_color="transparent")
        ctrl_row2.pack(fill="x", padx=15, pady=(2, 10))

        def gen_random_room():
            prefix = secrets.choice(["tactical-line", "som-unit", "kyberon-room", "delta-team", "phoenix-link"])
            num = secrets.randbelow(9000) + 1000
            rand_room = f"{prefix}-{num}"
            rand_key = secrets.token_urlsafe(12)

            room_in.delete(0, "end")
            room_in.insert(0, rand_room)
            room_key_in.delete(0, "end")
            room_key_in.insert(0, rand_key)
            sync_inputs()
            messagebox.showinfo(
                get_text("chat_alert_room_ready_title"),
                get_text("chat_alert_room_ready_msg", room=rand_room, key=rand_key)
            )

        def copy_room_invite():
            sync_inputs()
            r = self.p2p_saved_room
            k = self.p2p_saved_key
            if not r or not k:
                messagebox.showwarning("Warning", "Please specify room name and room key first!")
                return
            invite = get_text("chat_invite_template", room=r, key=k)
            self.clipboard_clear()
            self.clipboard_append(invite)
            messagebox.showinfo(
                get_text("chat_alert_invite_copied_title"),
                get_text("chat_alert_invite_copied_msg")
            )

        def trigger_pq_handshake():
            if not self.p2p_session or not self.p2p_session.is_connected:
                messagebox.showwarning("Not Connected", get_text("chat_alert_not_connected"))
                return
            self.p2p_session.initiate_pq_handshake()

        def clear_chat():
            self.p2p_message_history.clear()
            for w in self.p2p_messages_box.winfo_children():
                w.destroy()

        gen_btn = ctk.CTkButton(ctrl_row2, text=get_text("chat_btn_rand_room"), font=ctk.CTkFont(size=11), fg_color="#1e293b", hover_color="#334155", text_color="#38bdf8", width=145, height=28, command=gen_random_room)
        gen_btn.pack(side="left", padx=3)

        copy_btn = ctk.CTkButton(ctrl_row2, text=get_text("chat_btn_copy_invite"), font=ctk.CTkFont(size=11), fg_color="#1e293b", hover_color="#334155", text_color="#4ade80", width=140, height=28, command=copy_room_invite)
        copy_btn.pack(side="left", padx=3)

        pq_btn = ctk.CTkButton(ctrl_row2, text=get_text("btn_pq_handshake"), font=ctk.CTkFont(size=11, weight="bold"), fg_color="#3b0764", hover_color="#581c87", text_color="#e9d5ff", width=185, height=28, command=trigger_pq_handshake)
        pq_btn.pack(side="left", padx=3)

        clr_btn = ctk.CTkButton(ctrl_row2, text=get_text("chat_btn_zeroize"), font=ctk.CTkFont(size=11), fg_color="#1e293b", hover_color="#334155", text_color="#f87171", width=155, height=28, command=clear_chat)
        clr_btn.pack(side="left", padx=3)

        # Message Stream Box
        self.p2p_messages_box = ctk.CTkScrollableFrame(chat_layout, fg_color="#0b1120", corner_radius=10)
        self.p2p_messages_box.grid(row=1, column=0, sticky="nsew", pady=(0, 8))

        # Replay unexpired message history
        now = time.time()
        self.p2p_message_history = [
            m for m in self.p2p_message_history
            if not (m.get("burn") and (now - m.get("time_recv", 0) >= 30))
        ]
        for msg_record in self.p2p_message_history:
            self._render_single_p2p_bubble(msg_record)

        # Bottom Input Area
        bot_send = ctk.CTkFrame(chat_layout, fg_color="transparent")
        bot_send.grid(row=2, column=0, sticky="ew")
        bot_send.grid_columnconfigure(1, weight=1)

        burn_var = ctk.BooleanVar(value=self.p2p_burn_enabled)

        def on_burn_toggle():
            self.p2p_burn_enabled = burn_var.get()

        burn_chk = ctk.CTkCheckBox(bot_send, text=get_text("chat_burn_label"), variable=burn_var, command=on_burn_toggle, font=ctk.CTkFont(size=11), text_color="#f87171", width=105)
        burn_chk.grid(row=0, column=0, padx=(0, 8))

        msg_input = ctk.CTkEntry(bot_send, placeholder_text=get_text("chat_input_ph"), height=40)
        msg_input.grid(row=0, column=1, sticky="ew", padx=(0, 8))

        def send_file_p2p():
            if not self.p2p_session or not self.p2p_session.is_connected:
                messagebox.showwarning("Not Connected", get_text("chat_alert_not_connected"))
                return

            fpath = filedialog.askopenfilename(
                title=get_text("chat_file_dialog_title"),
                filetypes=[("All Files", "*.*")]
            )
            if not fpath:
                return

            fsize = os.path.getsize(fpath)
            if fsize > 1536 * 1024:
                messagebox.showerror("Error", get_text("chat_file_limit_err", size=fsize // 1024))
                return

            fname = os.path.basename(fpath)
            with open(fpath, "rb") as f:
                raw_bytes = f.read()

            b64_data = base64.b64encode(raw_bytes).decode("ascii")
            file_payload = json.dumps({
                "type": "file",
                "filename": fname,
                "size": fsize,
                "data": b64_data
            })

            packet = f"[FILE-DROP]: {file_payload}"
            if self.p2p_session.send_message(packet):
                messagebox.showinfo("Sent", get_text("chat_file_sent", fname=fname))

        def send_p2p(event=None):
            txt = msg_input.get().strip()
            if not txt:
                return
            if not self.p2p_session or not self.p2p_session.is_connected:
                messagebox.showwarning("Not Connected", get_text("chat_alert_not_connected"))
                return
            payload_txt = f"[BURNT-30]: {txt}" if burn_var.get() else txt
            if self.p2p_session.send_message(payload_txt):
                msg_input.delete(0, "end")

        msg_input.bind("<Return>", send_p2p)

        file_btn = ctk.CTkButton(bot_send, text=get_text("chat_btn_file"), font=ctk.CTkFont(size=12, weight="bold"), fg_color="#10b981", hover_color="#059669", width=85, height=40, command=send_file_p2p)
        file_btn.grid(row=0, column=2, padx=(0, 6))

        send_btn = ctk.CTkButton(bot_send, text=get_text("btn_send"), fg_color="#0284c7", width=100, height=40, command=send_p2p)
        send_btn.grid(row=0, column=3)

    # =========================================================================
    # 6. AIR-GAPPED MILITARY OPTICAL QR CRYPTOGRAPHY
    # =========================================================================
    def _render_airgap_view(self, parent):
        parent.grid_rowconfigure(1, weight=1)

        info_card = ctk.CTkFrame(parent, fg_color="#14532d", border_width=1, border_color="#16a34a", corner_radius=10)
        info_card.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        info_lbl = ctk.CTkLabel(info_card, text=get_text("airgap_desc"), font=ctk.CTkFont(size=12), text_color="#bbf7d0", justify="left", wraplength=820)
        info_lbl.pack(padx=16, pady=10, anchor="w")

        tabview = ctk.CTkTabview(parent)
        tabview.grid(row=1, column=0, sticky="nsew")
        tab_tx = tabview.add(get_text("tab_airgap_tx"))
        tab_rx = tabview.add(get_text("tab_airgap_rx"))
        tab_stego = tabview.add(get_text("tab_airgap_stego"))

        # --- TAB 1: TRANSMITTER (TX) ---
        tab_tx.grid_columnconfigure(0, weight=1)
        tab_tx.grid_columnconfigure(1, weight=1)

        tx_left = ctk.CTkFrame(tab_tx, fg_color="transparent")
        tx_left.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        ctk.CTkLabel(tx_left, text=get_text("airgap_tx_secret_label"), font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", pady=(0, 4))
        tx_input = ctk.CTkTextbox(tx_left, height=130, font=ctk.CTkFont(family="Consolas", size=12))
        tx_input.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(tx_left, text=get_text("airgap_tx_pass_label"), font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", pady=(0, 4))
        tx_key = ctk.CTkEntry(tx_left, placeholder_text=get_text("airgap_tx_pass_ph"), show="*", height=36)
        tx_key.pack(fill="x", pady=(0, 15))

        tx_right = ctk.CTkFrame(tab_tx, fg_color="#0b1120", corner_radius=12)
        tx_right.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

        qr_display_lbl = ctk.CTkLabel(tx_right, text=get_text("airgap_qr_placeholder"), text_color="#64748b")
        qr_display_lbl.pack(expand=True, pady=10)

        tx_current_img = {"pil": None}

        def do_generate_qr():
            txt = tx_input.get("1.0", "end").strip()
            if not txt:
                messagebox.showerror("Error", "Please enter payload to transmit!")
                return
            key = tx_key.get().strip() or None
            try:
                pil_img, token = airgap_crypto.generate_airgap_qr(txt, key)
                tx_current_img["pil"] = pil_img
                ctk_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(240, 240))
                qr_display_lbl.configure(image=ctk_img, text="")
                save_qr_btn.configure(state="normal")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate QR: {e}")

        def do_save_qr():
            if not tx_current_img["pil"]:
                return
            dest = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG Image", "*.png")],
                title=get_text("airgap_btn_save_qr")
            )
            if dest:
                tx_current_img["pil"].save(dest)
                messagebox.showinfo("Saved", get_text("airgap_qr_saved", dest=dest))

        gen_qr_btn = ctk.CTkButton(tx_left, text=get_text("airgap_btn_gen_qr"), font=ctk.CTkFont(size=13, weight="bold"), fg_color="#059669", hover_color="#047857", height=40, command=do_generate_qr)
        gen_qr_btn.pack(fill="x", pady=(0, 8))

        save_qr_btn = ctk.CTkButton(tx_left, text=get_text("airgap_btn_save_qr"), fg_color="#1e293b", hover_color="#334155", text_color="#38bdf8", height=34, state="disabled", command=do_save_qr)
        save_qr_btn.pack(fill="x")

        # --- TAB 2: RECEIVER (RX) ---
        tab_rx.grid_columnconfigure(0, weight=1)

        rx_frame = ctk.CTkFrame(tab_rx, fg_color="transparent")
        rx_frame.pack(fill="both", expand=True, padx=20, pady=15)

        top_rx_btns = ctk.CTkFrame(rx_frame, fg_color="transparent")
        top_rx_btns.pack(fill="x", pady=(0, 10))

        def load_qr_file():
            fpath = filedialog.askopenfilename(
                title="Select QR Image File",
                filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")]
            )
            if not fpath:
                return
            try:
                decoded_str = airgap_crypto.decode_airgap_image(fpath)
                rx_token_entry.delete("1.0", "end")
                rx_token_entry.insert("1.0", decoded_str)
                messagebox.showinfo("Detected", get_text("airgap_qr_loaded", count=len(decoded_str)))
            except Exception as e:
                messagebox.showerror("Error", str(e))

        load_img_btn = ctk.CTkButton(top_rx_btns, text=get_text("airgap_btn_load_img"), fg_color="#0284c7", hover_color="#0369a1", height=36, command=load_qr_file)
        load_img_btn.pack(side="left", padx=(0, 10))

        ctk.CTkLabel(rx_frame, text=get_text("airgap_rx_token_label"), font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", pady=(5, 3))
        rx_token_entry = ctk.CTkTextbox(rx_frame, height=90, font=ctk.CTkFont(family="Consolas", size=11))
        rx_token_entry.pack(fill="x", pady=(0, 8))

        ctk.CTkLabel(rx_frame, text=get_text("airgap_rx_pass_label"), font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", pady=(5, 3))
        rx_key_entry = ctk.CTkEntry(rx_frame, placeholder_text=get_text("airgap_rx_pass_ph"), show="*", height=36)
        rx_key_entry.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(rx_frame, text=get_text("airgap_rx_result_label"), font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", pady=(5, 3))
        rx_result_box = ctk.CTkTextbox(rx_frame, height=100, font=ctk.CTkFont(family="Consolas", size=12))
        rx_result_box.pack(fill="x", pady=(0, 10))

        def do_decrypt_qr():
            raw_token = rx_token_entry.get("1.0", "end").strip()
            if not raw_token:
                messagebox.showerror("Error", "Please load or paste a QR token!")
                return
            key = rx_key_entry.get().strip() or None
            try:
                plain = airgap_crypto.decrypt_airgap_token(raw_token, key)
                rx_result_box.delete("1.0", "end")
                rx_result_box.insert("1.0", plain)
                messagebox.showinfo("Success", get_text("airgap_decrypt_success"))
            except Exception as e:
                messagebox.showerror("Error", str(e))

        decrypt_btn = ctk.CTkButton(rx_frame, text=get_text("airgap_btn_decrypt"), font=ctk.CTkFont(size=13, weight="bold"), fg_color="#059669", hover_color="#047857", height=40, command=do_decrypt_qr)
        decrypt_btn.pack(fill="x")

        # --- TAB 3: IMAGE STEGANOGRAPHY (LSB) ---
        tab_stego.grid_columnconfigure(0, weight=1)
        tab_stego.grid_columnconfigure(1, weight=1)

        # Left Column: Embed
        stego_left = ctk.CTkFrame(tab_stego, fg_color="transparent")
        stego_left.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        ctk.CTkLabel(stego_left, text=get_text("stego_embed_title"), font=ctk.CTkFont(size=13, weight="bold"), text_color="#38bdf8").pack(anchor="w", pady=(0, 6))

        ctk.CTkLabel(stego_left, text=get_text("stego_cover_label"), font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", pady=(2, 2))
        cover_row = ctk.CTkFrame(stego_left, fg_color="transparent")
        cover_row.pack(fill="x", pady=(0, 8))
        cover_path_entry = ctk.CTkEntry(cover_row, placeholder_text="C:/path/to/image.png", height=32)
        cover_path_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))

        def choose_cover_img():
            f = filedialog.askopenfilename(
                title=get_text("stego_cover_label"),
                filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")]
            )
            if f:
                cover_path_entry.delete(0, "end")
                cover_path_entry.insert(0, f)

        choose_cover_btn = ctk.CTkButton(cover_row, text=get_text("stego_btn_choose_img"), width=120, height=32, command=choose_cover_img)
        choose_cover_btn.pack(side="right")

        ctk.CTkLabel(stego_left, text=get_text("stego_secret_label"), font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", pady=(2, 2))
        stego_secret_in = ctk.CTkTextbox(stego_left, height=90, font=ctk.CTkFont(family="Consolas", size=11))
        stego_secret_in.pack(fill="x", pady=(0, 8))

        ctk.CTkLabel(stego_left, text=get_text("stego_pass_label"), font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", pady=(2, 2))
        stego_embed_pass = ctk.CTkEntry(stego_left, placeholder_text=get_text("stego_pass_ph"), show="*", height=32)
        stego_embed_pass.pack(fill="x", pady=(0, 12))

        def do_embed_secret():
            cov = cover_path_entry.get().strip()
            sec = stego_secret_in.get("1.0", "end").strip()
            if not cov or not os.path.exists(cov):
                messagebox.showerror("Error", "Please select a valid cover image!")
                return
            if not sec:
                messagebox.showerror("Error", "Please enter the secret payload to embed!")
                return
            dest = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG Image", "*.png")],
                title=get_text("stego_btn_embed")
            )
            if not dest:
                return
            pw = stego_embed_pass.get().strip() or None
            try:
                out = steganography.embed_secret_in_image(cov, sec, pw, dest)
                messagebox.showinfo("Success", get_text("stego_embed_success", dest=out))
            except Exception as e:
                messagebox.showerror("Error", f"Steganography failed: {e}")

        embed_btn = ctk.CTkButton(stego_left, text=get_text("stego_btn_embed"), font=ctk.CTkFont(size=12, weight="bold"), fg_color="#059669", hover_color="#047857", height=38, command=do_embed_secret)
        embed_btn.pack(fill="x")

        # Right Column: Extract
        stego_right = ctk.CTkFrame(tab_stego, fg_color="transparent")
        stego_right.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

        ctk.CTkLabel(stego_right, text=get_text("stego_extract_title"), font=ctk.CTkFont(size=13, weight="bold"), text_color="#4ade80").pack(anchor="w", pady=(0, 6))

        ctk.CTkLabel(stego_right, text=get_text("stego_stego_label"), font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", pady=(2, 2))
        stego_row = ctk.CTkFrame(stego_right, fg_color="transparent")
        stego_row.pack(fill="x", pady=(0, 8))
        stego_path_entry = ctk.CTkEntry(stego_row, placeholder_text="C:/path/to/stego.png", height=32)
        stego_path_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))

        def choose_stego_img():
            f = filedialog.askopenfilename(
                title=get_text("stego_stego_label"),
                filetypes=[("PNG Image", "*.png"), ("All Files", "*.*")]
            )
            if f:
                stego_path_entry.delete(0, "end")
                stego_path_entry.insert(0, f)

        choose_stego_btn = ctk.CTkButton(stego_row, text=get_text("stego_btn_choose_img"), width=120, height=32, command=choose_stego_img)
        choose_stego_btn.pack(side="right")

        ctk.CTkLabel(stego_right, text=get_text("stego_decrypt_pass_label"), font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", pady=(2, 2))
        stego_extract_pass = ctk.CTkEntry(stego_right, placeholder_text=get_text("stego_decrypt_pass_ph"), show="*", height=32)
        stego_extract_pass.pack(fill="x", pady=(0, 8))

        ctk.CTkLabel(stego_right, text=get_text("stego_result_label"), font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", pady=(2, 2))
        stego_res_box = ctk.CTkTextbox(stego_right, height=90, font=ctk.CTkFont(family="Consolas", size=11))
        stego_res_box.pack(fill="x", pady=(0, 8))

        def do_extract_secret():
            steg_p = stego_path_entry.get().strip()
            if not steg_p or not os.path.exists(steg_p):
                messagebox.showerror("Error", "Please select a valid stego PNG image!")
                return
            pw = stego_extract_pass.get().strip() or None
            try:
                recovered = steganography.extract_secret_from_image(steg_p, pw)
                stego_res_box.delete("1.0", "end")
                stego_res_box.insert("1.0", recovered)
                messagebox.showinfo("Success", get_text("stego_extract_success"))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to extract secret: {e}")

        extract_btn = ctk.CTkButton(stego_right, text=get_text("stego_btn_extract"), font=ctk.CTkFont(size=12, weight="bold"), fg_color="#0284c7", hover_color="#0369a1", height=38, command=do_extract_secret)
        extract_btn.pack(fill="x")

    # =========================================================================
    # 7. SHAMIR'S SECRET SHARING (SSS)
    # =========================================================================
    def _render_shamir_view(self, parent):
        parent.grid_rowconfigure(1, weight=1)

        info_card = ctk.CTkFrame(parent, fg_color="#064e3b", border_width=1, border_color="#059669", corner_radius=10)
        info_card.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        info_lbl = ctk.CTkLabel(info_card, text=get_text("shamir_desc"), font=ctk.CTkFont(size=12), text_color="#a7f3d0", justify="left")
        info_lbl.pack(padx=16, pady=10, anchor="w")

        tabview = ctk.CTkTabview(parent)
        tabview.grid(row=1, column=0, sticky="nsew")
        tab_split = tabview.add(get_text("tab_split"))
        tab_combine = tabview.add(get_text("tab_combine"))

        sec_in = ctk.CTkTextbox(tab_split, height=70, font=ctk.CTkFont(family="Consolas", size=12))
        sec_in.pack(fill="x", padx=15, pady=6)
        sec_in.insert("1.0", "witch collapse practice feed shame open despair creek road again ice least")

        opts_frame = ctk.CTkFrame(tab_split, fg_color="transparent")
        opts_frame.pack(fill="x", padx=15, pady=4)
        ctk.CTkLabel(opts_frame, text=get_text("label_n")).pack(side="left", padx=5)
        n_menu = ctk.CTkOptionMenu(opts_frame, values=["3", "4", "5", "6", "7"], width=70)
        n_menu.set("5")
        n_menu.pack(side="left", padx=5)

        ctk.CTkLabel(opts_frame, text=get_text("label_k")).pack(side="left", padx=15)
        k_menu = ctk.CTkOptionMenu(opts_frame, values=["2", "3", "4", "5"], width=70)
        k_menu.set("3")
        k_menu.pack(side="left", padx=5)

        out_text = ctk.CTkTextbox(tab_split, height=130, font=ctk.CTkFont(family="Consolas", size=11))
        out_text.pack(fill="both", expand=True, padx=15, pady=6)

        def do_split():
            text = sec_in.get("1.0", "end").strip()
            if not text:
                return
            n = int(n_menu.get())
            k = int(k_menu.get())
            if k > n:
                messagebox.showerror("Error", "Threshold K cannot exceed total N!")
                return
            shares = crypto_utils.shamir_split(text, k, n)
            out_text.delete("1.0", "end")
            out_text.insert("1.0", "\n\n".join(shares))

        split_btn = ctk.CTkButton(tab_split, text=get_text("btn_do_split"), fg_color="#0284c7", command=do_split)
        split_btn.pack(pady=8, padx=15, fill="x")

        # Combine Tab
        comb_in = ctk.CTkTextbox(tab_combine, height=120, font=ctk.CTkFont(family="Consolas", size=11))
        comb_in.pack(fill="x", padx=15, pady=4)

        comb_out = ctk.CTkTextbox(tab_combine, height=70, font=ctk.CTkFont(family="Consolas", size=12))
        comb_out.pack(fill="x", padx=15, pady=6)

        def do_combine():
            raw = comb_in.get("1.0", "end").strip().splitlines()
            try:
                secret = crypto_utils.shamir_combine(raw)
                comb_out.delete("1.0", "end")
                comb_out.insert("1.0", secret)
                messagebox.showinfo("Success", get_text("shamir_success_msg"))
            except Exception as e:
                messagebox.showerror("Error", f"Recovery error: {e}")

        comb_btn = ctk.CTkButton(tab_combine, text=get_text("btn_do_combine"), fg_color="#059669", command=do_combine)
        comb_btn.pack(pady=8, padx=15, fill="x")

    # =========================================================================
    # 8. BIP-39 SEED ANALYZER & CRYPTO GUIDE
    # =========================================================================
    def _render_bip39_view(self, parent):
        lbl_head = ctk.CTkLabel(parent, text=get_text("bip39_title"), font=ctk.CTkFont(size=18, weight="bold"), text_color="#38bdf8")
        lbl_head.pack(pady=(10, 6), anchor="w")

        seed_box = ctk.CTkTextbox(parent, height=90, font=ctk.CTkFont(family="Consolas", size=13))
        seed_box.pack(fill="x", pady=6)
        seed_box.insert("1.0", "witch collapse practice feed shame open despair creek road again ice least")

        res_card = ctk.CTkFrame(parent, fg_color="#0f172a", corner_radius=10)
        res_card.pack(fill="x", pady=10)

        res_lbl = ctk.CTkLabel(res_card, text="", font=ctk.CTkFont(size=13), justify="left")
        res_lbl.pack(padx=16, pady=12, anchor="w")

        def analyze():
            text = seed_box.get("1.0", "end").strip()
            res = crypto_utils.validate_bip39_seed(text)
            color = "#4ade80" if res["is_valid_length"] and res["is_valid_format"] else "#ef4444"
            len_str = get_text("bip39_valid_len") if res["is_valid_length"] else get_text("bip39_invalid_len")
            fmt_str = get_text("bip39_valid_fmt") if res["is_valid_format"] else get_text("bip39_invalid_fmt")
            res_lbl.configure(
                text=(
                    f"{get_text('bip39_word_count', count=res['word_count'])}\n"
                    f"{len_str}\n"
                    f"{fmt_str}\n"
                    f"{get_text('bip39_entropy', bits=res['entropy_bits'])}\n"
                    f"{get_text('bip39_result', status=res['standard_status'])}"
                ),
                text_color=color
            )

        btn = ctk.CTkButton(parent, text=get_text("bip39_btn_analyze"), fg_color="#0284c7", command=analyze, height=36)
        btn.pack(fill="x", pady=6)
        analyze()

    def _render_guide_view(self, parent):
        scroll = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        guide_texts = {
            "tr": [
                ("🛡️ AES-256-GCM Neden Endüstri ve Devlet Standardıdır?", 
                 "AES-256, ABD Ulusal Güvenlik Ajansı (NSA) tarafından 'Top Secret' düzeyindeki devlet sırlarını korumak için onaylanan CNSA Suite standardıdır. GCM (Galois/Counter Mode) modu ise şifreli metinle birlikte 128-bitlik bir doğrulama etiketi (Auth Tag) üretir. Dosyadaki tek bir harf veya bit değiştirilse dahi sistem bunu fark eder ve işlemi iptal eder."),
                ("🔒 scrypt ve GPU Brute-Force Direnci", 
                 "Standart SHA-256 veya MD5 algoritmaları bellek kullanmaz; bu yüzden GPU çiftlikleriyle saniyede milyarlarca parola denenebilir. Kyberon'da kullanılan 'scrypt' algoritması her denemede ~32 MB RAM ayrılmasını zorunlu kılar; GPU'lar bellek darboğazına girer ve kaba kuvvet saldırısı imkansız hale gelir."),
                ("🧩 Shamir's Secret Sharing (SSS) Nedir?", 
                 "Bir sırrı N parçaya böler ve K tanesi bir araya gelmeden çözülmesini matematiksel olarak imkansız kılar. 3-of-5 sisteminde oluşturulan parçalar farklı yerlere dağıtılabilir; yangın veya hırsızlık durumunda 2 parça yok olsa bile paranız güvendedir."),
                ("🎭 Tehdit Parolası (Duress Password / Plausible Deniability)", 
                 "Fiziksel baskı altındayken girilebilecek sahte bir paroladır. Sistem gerçek veriler yerine sıradan önemsiz hesapların bulunduğu sahte bir kasa açar; saldırgan gerçek kasanın varlığını matematiksel olarak kanıtlayamaz."),
                ("🔒 Cihaza Özel Donanım İmzası (Hardware Binding)",
                 "Anahtar türetimi bilgisayarınızın anakart ve donanım kimliğiyle harmanlanır. Kasa dosyanız çalınıp başka bir bilgisayara götürülse bile doğru parola girilse dahi açılamaz.")
            ],
            "en": [
                ("🛡️ Why is AES-256-GCM the Gold Standard for Encryption?",
                 "AES-256 is certified by the NSA CNSA Suite for protecting Top Secret state secrets. The Galois/Counter Mode (GCM) computes a 128-bit authentication tag alongside the ciphertext. If even a single bit in the file is modified or tampered with, decryption instantly aborts with an integrity fault."),
                ("🔒 scrypt & GPU Brute-Force Resistance",
                 "Standard hashes like SHA-256 require no memory, allowing GPU clusters to attempt billions of passwords per second. Kyberon utilizes scrypt with memory-hard parameters (~32 MB RAM per attempt), paralyzing GPU/ASIC brute-force dictionary attacks."),
                ("🧩 What is Shamir's Secret Sharing (SSS)?",
                 "Invented by cryptographer Adi Shamir, SSS splits a cryptographic secret into N shares such that any K threshold must unite to reconstruct it. In a 3-of-5 setup, losing or leaking 2 shares compromises zero information."),
                ("🎭 Duress Password & Plausible Deniability",
                 "If compelled to open your vault under physical threat, entering the duress password decrypts an alternate decoy vault populated with innocuous data. An adversary cannot mathematically prove the existence of the real vault."),
                ("🔒 Hardware Fingerprint Binding",
                 "Ties cryptographic key derivation to your motherboard and machine architecture. Even if the encrypted .mvat file is exfiltrated, it cannot be decrypted on any other computer.")
            ],
            "ru": [
                ("🛡️ Почему AES-256-GCM — военный стандарт?",
                 "AES-256 сертифицирован АНБ США для защиты данных уровня 'Top Secret'. Режим GCM создает 128-битный аутентификационный тег. Изменение хотя бы одного бита приводит к немедленной блокировке расшифровки."),
                ("🔒 scrypt и защита от GPU-атак",
                 "Стандартные хеши не требуют памяти, что позволяет фермам GPU перебирать миллиарды паролей. scrypt в Kyberon требует ~32 МБ оперативной памяти на каждую попытку, парализуя перебор."),
                ("🧩 Разделение секрета Шамира (SSS)",
                 "Математически разделяет сид-фразу на N долей, требуя K долей для восстановления. При схеме 3 из 5 потеря или утечка 2 долей не раскрывает абсолютно ничего."),
                ("🎭 Пароль под принуждением (Duress Mode)",
                 "Позволяет ввести ложный пароль при физической угрозе. Открывается правдоподобное ложное хранилище. Доказать существование основного хранилища математически невозможно."),
                ("🔒 Привязка к оборудованию (Hardware Binding)",
                 "Шифрование привязывается к материнской плате и ID процессора. Украденный файл .mvat невозможно открыть на другом компьютере даже зная пароль.")
            ]
        }

        lang = i18n.CURRENT_LANG if i18n.CURRENT_LANG in guide_texts else "en"
        for title, body in guide_texts[lang]:
            card = ctk.CTkFrame(scroll, fg_color="#0f172a", corner_radius=10, border_width=1, border_color="#1e293b")
            card.pack(fill="x", pady=8, padx=4)
            ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=15, weight="bold"), text_color="#38bdf8").pack(anchor="w", padx=16, pady=(12, 4))
            ctk.CTkLabel(card, text=body, font=ctk.CTkFont(size=12), text_color="#cbd5e1", justify="left", wraplength=720).pack(anchor="w", padx=16, pady=(0, 14))

    # =========================================================================
    # 9. MILITARY AUDIT TRAIL & FIPS 140-3 SELF-TEST LOGS
    # =========================================================================
    def _render_audit_view(self, parent):
        scroll = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        post_card = ctk.CTkFrame(scroll, fg_color="#0f172a", corner_radius=10, border_width=1, border_color="#1e293b")
        post_card.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(post_card, text=get_text("audit_title"), font=ctk.CTkFont(size=15, weight="bold"), text_color="#38bdf8").pack(anchor="w", padx=16, pady=(12, 4))
        ctk.CTkLabel(post_card, text=get_text("audit_desc"), font=ctk.CTkFont(size=11), text_color="#94a3b8").pack(anchor="w", padx=16, pady=(0, 8))

        tests = getattr(self, "post_results", {}).get("tests", [])
        for t in tests:
            t_row = ctk.CTkFrame(post_card, fg_color="transparent")
            t_row.pack(fill="x", padx=16, pady=2)
            icon = "✅" if t["passed"] else "❌"
            ctk.CTkLabel(t_row, text=f"{icon} {t['name']}", font=ctk.CTkFont(size=12, weight="bold"), text_color="#4ade80" if t["passed"] else "#ef4444").pack(side="left")
            ctk.CTkLabel(t_row, text=f"- {t['details']}", font=ctk.CTkFont(size=11), text_color="#cbd5e1").pack(side="left", padx=8)

        act_box = ctk.CTkFrame(scroll, fg_color="transparent")
        act_box.pack(fill="x", pady=8)

        def verify_chain():
            ok, msg, count = military_audit.CryptographicAuditTrail.verify_integrity()
            if ok:
                messagebox.showinfo("Audit Integrity Passed", f"✅ {msg}")
            else:
                messagebox.showerror("Audit Integrity FAILED", f"❌ {msg}")

        def trigger_zeroize():
            msg = get_text("audit_zeroize_confirm_1", profile=self.selected_profile)
            if messagebox.askyesno("EMERGENCY ZEROIZE", msg):
                if messagebox.askyesno("CONFIRMATION", get_text("audit_zeroize_confirm_2")):
                    military_audit.emergency_zeroize_vault(self.selected_profile)
                    messagebox.showinfo("Zeroize Complete", get_text("audit_zeroize_complete"))
                    sys.exit(0)

        ctk.CTkButton(act_box, text=get_text("audit_btn_verify"), fg_color="#0284c7", command=verify_chain, height=36).pack(side="left", padx=4)
        ctk.CTkButton(act_box, text=get_text("audit_btn_zeroize"), fg_color="#7f1d1d", hover_color="#991b1b", command=trigger_zeroize, height=36).pack(side="right", padx=4)

        # Dead-Man's Switch & Scorched-Earth Brute-Force Shield Card
        dms_card = ctk.CTkFrame(scroll, fg_color="#1c1917", corner_radius=10, border_width=1, border_color="#7f1d1d")
        dms_card.pack(fill="x", pady=(6, 10))

        ctk.CTkLabel(
            dms_card,
            text=get_text("dms_card_title"),
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#f87171"
        ).pack(anchor="w", padx=16, pady=(10, 2))

        ctk.CTkLabel(
            dms_card,
            text=get_text("dms_card_desc"),
            font=ctk.CTkFont(size=11),
            text_color="#d6d3d1",
            justify="left",
            wraplength=780
        ).pack(anchor="w", padx=16, pady=(0, 8))

        cur_policy = vault_storage.get_profile_security_policy(self.selected_profile)
        dms_row = ctk.CTkFrame(dms_card, fg_color="transparent")
        dms_row.pack(fill="x", padx=16, pady=(0, 12))

        ctk.CTkLabel(dms_row, text=get_text("dms_inactivity_lbl"), font=ctk.CTkFont(size=11, weight="bold")).pack(side="left", padx=(0, 6))
        dms_menu = ctk.CTkOptionMenu(dms_row, values=["0", "7", "30", "90", "180"], width=80, height=28)
        dms_menu.set(str(cur_policy.get("dms_days", 0)))
        dms_menu.pack(side="left", padx=(0, 16))

        ctk.CTkLabel(dms_row, text=get_text("dms_bruteforce_lbl"), font=ctk.CTkFont(size=11, weight="bold")).pack(side="left", padx=(0, 6))
        bf_menu = ctk.CTkOptionMenu(dms_row, values=["0", "10", "15", "25"], width=80, height=28)
        bf_menu.set(str(cur_policy.get("max_failed_wipe", 0)))
        bf_menu.pack(side="left", padx=(0, 16))

        def save_dms_policy():
            d_val = int(dms_menu.get())
            b_val = int(bf_menu.get())
            vault_storage.configure_profile_security_policy(self.selected_profile, d_val, b_val)
            messagebox.showinfo("Security Policy Sealed", get_text("dms_saved_msg", dms=d_val, bf=b_val))
            self.render_active_tab()

        ctk.CTkButton(
            dms_row,
            text=get_text("dms_save_btn"),
            fg_color="#dc2626",
            hover_color="#b91c1c",
            font=ctk.CTkFont(size=11, weight="bold"),
            height=28,
            command=save_dms_policy
        ).pack(side="right")

        log_head = ctk.CTkLabel(scroll, text=get_text("audit_log_title"), font=ctk.CTkFont(size=14, weight="bold"))
        log_head.pack(anchor="w", pady=(10, 4))

        events = military_audit.CryptographicAuditTrail.get_recent_events(limit=25)
        for ev in events:
            ev_card = ctk.CTkFrame(scroll, fg_color="#111827", corner_radius=8, border_width=1, border_color="#1f2937")
            ev_card.pack(fill="x", pady=3)

            top_line = ctk.CTkFrame(ev_card, fg_color="transparent")
            top_line.pack(fill="x", padx=12, pady=(6, 2))
            ctk.CTkLabel(top_line, text=f"Block #{ev['index']} [{ev['timestamp']}]", font=ctk.CTkFont(size=11, weight="bold"), text_color="#38bdf8").pack(side="left")
            ctk.CTkLabel(top_line, text=f"Event: {ev['event_type']} ({ev['actor']})", font=ctk.CTkFont(size=11), text_color="#f8fafc").pack(side="left", padx=10)

            hash_txt = f"Hash: {ev['hash'][:24]}... | Prev: {ev['prev_hash'][:16]}..."
            ctk.CTkLabel(ev_card, text=f"{ev['details']} | {hash_txt}", font=ctk.CTkFont(family="Consolas", size=10), text_color="#64748b").pack(anchor="w", padx=12, pady=(0, 6))


if __name__ == "__main__":
    app = KyberonApp()
    app.mainloop()
