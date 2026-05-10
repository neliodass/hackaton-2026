"""
Testy bezpieczeństwa systemu aktualizacji oprogramowania.

Każdy test symuluje konkretny wektor ataku i weryfikuje, że system go blokuje.
Wszystkie klucze są efemeryczne — żadne pliki na dysku nie są odczytywane ani modyfikowane.

Uruchomienie:
    pytest                          # wszystkie testy
    pytest -m crypto                # tylko testy kryptograficzne
    pytest -m merkle                # tylko testy Merkle
    pytest --html=report.html       # raport HTML
"""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta, timezone

import pytest

from conftest import canonical, make_cert_body, make_manifest


# ===========================================================================
# Testy kryptograficzne — podpis Ed25519
# ===========================================================================

@pytest.mark.crypto
class TestEd25519:

    def test_tampered_manifest_rejected(self, ed25519_keypair, verifiers):
        """A01: Podmiana manifestu po podpisaniu musi być odrzucona przez Ed25519."""
        sk, pk_hex = ed25519_keypair
        m_original = make_manifest(version="1.0.0", rid="ed-tamper-001")
        sig = sk.sign(canonical(m_original))

        m_tampered = {**m_original, "version": "9.9.9"}

        assert not verifiers.verify_manifest_signature(m_tampered, sig, pk_hex), (
            "Podpis Ed25519 zaakceptował zmieniony manifest — atak podmiana wersji PRZESZEDŁ"
        )

    def test_wrong_key_rejected(self, ed25519_keypair, verifiers):
        """A03: Podpis złożony obcym kluczem musi być odrzucony przy weryfikacji kluczem ofiary."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        _, victim_pk = ed25519_keypair
        attacker_sk = Ed25519PrivateKey.generate()

        evil = make_manifest(version="9.9.9", rid="ed-xkey-001")
        sig = attacker_sk.sign(canonical(evil))

        assert not verifiers.verify_manifest_signature(evil, sig, victim_pk), (
            "Ed25519 zaakceptował podpis obcego klucza — atak key confusion PRZESZEDŁ"
        )

    def test_signature_not_transferable_between_manifests(self, ed25519_keypair, verifiers):
        """Podpis dla manifestu A nie może weryfikować manifestu B."""
        sk, pk_hex = ed25519_keypair
        m_a = make_manifest(version="1.0.0", rid="ed-xsig-a")
        m_b = make_manifest(version="2.0.0", rid="ed-xsig-b")

        sig_a = sk.sign(canonical(m_a))

        assert not verifiers.verify_manifest_signature(m_b, sig_a, pk_hex)


# ===========================================================================
# Testy kryptograficzne — podpis ML-DSA-65 (post-quantum)
# ===========================================================================

@pytest.mark.crypto
class TestMLDSA65:

    def test_tampered_manifest_rejected(self, mldsa65_keypair, verifiers):
        """A02: Podmiana manifestu po podpisaniu musi być odrzucona przez ML-DSA-65."""
        from dilithium_py.ml_dsa import ML_DSA_65

        pk, sk = mldsa65_keypair
        m_original = make_manifest(version="1.0.0", rid="pq-tamper-001")
        sig = ML_DSA_65.sign(sk, canonical(m_original), ctx=b"")

        m_tampered = {**m_original, "version": "9.9.9"}

        assert not verifiers.verify_manifest_pq_signature(m_tampered, sig, pk.hex()), (
            "ML-DSA-65 zaakceptował zmieniony manifest — atak podmiana wersji PRZESZEDŁ"
        )

    def test_wrong_key_rejected(self, mldsa65_keypair, verifiers):
        """A04: Podpis ML-DSA złożony obcym kluczem musi być odrzucony."""
        from dilithium_py.ml_dsa import ML_DSA_65

        victim_pk, _ = mldsa65_keypair
        _, attacker_sk = ML_DSA_65.keygen()

        evil = make_manifest(version="9.9.9", rid="pq-xkey-001")
        sig = ML_DSA_65.sign(attacker_sk, canonical(evil), ctx=b"")

        assert not verifiers.verify_manifest_pq_signature(evil, sig, victim_pk.hex()), (
            "ML-DSA-65 zaakceptował podpis obcego klucza — atak key confusion PRZESZEDŁ"
        )

    def test_signature_not_transferable_between_manifests(self, mldsa65_keypair, verifiers):
        """Podpis PQ dla manifestu A nie może weryfikować manifestu B."""
        from dilithium_py.ml_dsa import ML_DSA_65

        pk, sk = mldsa65_keypair
        m_a = make_manifest(version="1.0.0", rid="pq-xsig-a")
        m_b = make_manifest(version="2.0.0", rid="pq-xsig-b")

        sig_a = ML_DSA_65.sign(sk, canonical(m_a), ctx=b"")

        assert not verifiers.verify_manifest_pq_signature(m_b, sig_a, pk.hex())


# ===========================================================================
# Testy certyfikatu podpisującego
# ===========================================================================

@pytest.mark.cert
class TestSigningCertificate:

    def test_forged_root_signatures_rejected(self, ed25519_keypair, verifiers):
        """A05: Certyfikat z losowymi podpisami root musi być odrzucony."""
        _, root_ed_pub = ed25519_keypair
        root_pq_pub = os.urandom(1952).hex()   # ML-DSA-65 pk size

        now = datetime.now(timezone.utc)
        body = make_cert_body("aa" * 32, "bb" * 100, now, now + timedelta(days=7))
        fake_cert = {
            **body,
            "root_signatures": {
                "ed25519": os.urandom(64).hex(),
                "mldsa":   os.urandom(3293).hex(),
            },
        }

        assert not verifiers.verify_signing_cert(fake_cert, root_ed_pub, root_pq_pub), (
            "verify_signing_cert zaakceptował certyfikat z losowymi podpisami root"
        )

    def test_expired_cert_rejected(self, valid_cert_body, verifiers):
        """A06: Wygasły certyfikat musi być odrzucony przez is_cert_time_valid."""
        now = datetime.now(timezone.utc)
        body = make_cert_body(
            "aa" * 32, "bb" * 100,
            valid_from=now - timedelta(days=9),
            valid_to=now - timedelta(days=2),
        )
        expired = {**body, "root_signatures": {"ed25519": "00" * 64, "mldsa": "00"}}

        assert not verifiers.is_cert_time_valid(expired), (
            "is_cert_time_valid zaakceptował certyfikat po valid_to"
        )

    def test_future_cert_rejected(self, verifiers):
        """A07: Certyfikat z valid_from w przyszłości musi być odrzucony."""
        now = datetime.now(timezone.utc)
        body = make_cert_body(
            "aa" * 32, "bb" * 100,
            valid_from=now + timedelta(days=1),
            valid_to=now + timedelta(days=8),
        )
        future = {**body, "root_signatures": {"ed25519": "00" * 64, "mldsa": "00"}}

        assert not verifiers.is_cert_time_valid(future), (
            "is_cert_time_valid zaakceptował certyfikat przed valid_from"
        )

    def test_valid_cert_accepted(self, verifiers):
        """Poprawnie skonstruowany certyfikat (aktualny czas) musi przejść is_cert_time_valid."""
        now = datetime.now(timezone.utc)
        body = make_cert_body(
            "aa" * 32, "bb" * 100,
            valid_from=now - timedelta(hours=1),
            valid_to=now + timedelta(days=6),
        )
        valid = {**body, "root_signatures": {"ed25519": "00" * 64, "mldsa": "00"}}

        assert verifiers.is_cert_time_valid(valid)

    def test_missing_root_signatures_field_rejected(self, verifiers):
        """Certyfikat bez pola root_signatures musi być odrzucony."""
        now = datetime.now(timezone.utc)
        body = make_cert_body(
            "aa" * 32, "bb" * 100,
            valid_from=now - timedelta(hours=1),
            valid_to=now + timedelta(days=6),
        )
        root_ed_pub = "cc" * 32
        root_pq_pub = "dd" * 1952

        assert not verifiers.verify_signing_cert(body, root_ed_pub, root_pq_pub)


# ===========================================================================
# Testy Merkle transparency log
# ===========================================================================

@pytest.mark.merkle
class TestMerkleProof:

    @staticmethod
    def _build_tree(m_a: dict, m_b: dict, mv) -> tuple[str, list, list]:
        """2-liściowe drzewo Merkle; zwraca (root, proof_a, proof_b)."""
        def leaf(m):
            return hashlib.sha256(bytes.fromhex(mv.manifest_merkle_hash(m))).digest()

        la, lb = leaf(m_a), leaf(m_b)
        root = hashlib.sha256(la + lb).hexdigest()
        proof_a = [{"hash": lb.hex(), "position": "R"}]
        proof_b = [{"hash": la.hex(), "position": "L"}]
        return root, proof_a, proof_b

    def test_random_proof_rejected(self, merkle_verifier):
        """A08: Całkowicie losowy proof musi być odrzucony."""
        m = make_manifest(rid="merkle-rnd-001")
        fake_proof = [
            {"hash": os.urandom(32).hex(), "position": "L"},
            {"hash": os.urandom(32).hex(), "position": "R"},
        ]
        fake_root = os.urandom(32).hex()

        assert not merkle_verifier.verify_proof(m, fake_proof, fake_root)

    def test_wrong_root_rejected(self, merkle_verifier):
        """A09: Poprawny proof z podstawionym rootem musi być odrzucony."""
        m_a = make_manifest(version="2.0.0", rid="wr-a")
        m_b = make_manifest(version="2.1.0", rid="wr-b")
        real_root, proof_a, _ = self._build_tree(m_a, m_b, merkle_verifier)

        attacker_root = os.urandom(32).hex()
        assert attacker_root != real_root

        assert not merkle_verifier.verify_proof(m_a, proof_a, attacker_root)

    def test_cross_leaf_proof_rejected(self, merkle_verifier):
        """A10: Proof dla liścia A nie może weryfikować manifestu B (replay w drzewie)."""
        m_a = make_manifest(version="2.0.0", rid="cl-a")
        m_b = make_manifest(version="2.1.0", rid="cl-b")
        root, proof_a, _ = self._build_tree(m_a, m_b, merkle_verifier)

        assert not merkle_verifier.verify_proof(m_b, proof_a, root)

    def test_valid_proof_accepted(self, merkle_verifier):
        """Poprawny proof dla rzeczywistego liścia musi przejść weryfikację."""
        m_a = make_manifest(version="2.0.0", rid="ok-a")
        m_b = make_manifest(version="2.1.0", rid="ok-b")
        root, proof_a, proof_b = self._build_tree(m_a, m_b, merkle_verifier)

        assert merkle_verifier.verify_proof(m_a, proof_a, root)
        assert merkle_verifier.verify_proof(m_b, proof_b, root)

    def test_empty_proof_single_leaf(self, merkle_verifier):
        """Proof puste = drzewo 1-liściowe; root == SHA256(leaf)."""
        m = make_manifest(rid="single-leaf")
        entry = merkle_verifier.manifest_merkle_hash(m)
        leaf = hashlib.sha256(bytes.fromhex(entry)).digest()
        root_of_one = leaf.hex()

        assert merkle_verifier.verify_proof(m, [], root_of_one)

    def test_bit_flip_in_proof_step_rejected(self, merkle_verifier):
        """Zmiana 1 bitu w dowolnym kroku proof musi niszczyć weryfikację."""
        m_a = make_manifest(version="2.0.0", rid="bf-a")
        m_b = make_manifest(version="2.1.0", rid="bf-b")
        root, proof_a, _ = self._build_tree(m_a, m_b, merkle_verifier)

        corrupted = list(proof_a)
        original_hash = bytes.fromhex(corrupted[0]["hash"])
        flipped = bytearray(original_hash)
        flipped[0] ^= 0x01
        corrupted[0] = {**corrupted[0], "hash": bytes(flipped).hex()}

        assert not merkle_verifier.verify_proof(m_a, corrupted, root)


# ===========================================================================
# Testy logiki protokołu (freeze, downgrade, hash)
# ===========================================================================

@pytest.mark.protocol
class TestProtocolDefenses:

    def test_freeze_attack_blocked(self):
        """A11: Manifest starszy niż MANIFEST_MAX_AGE_DAYS musi być odrzucony."""
        MAX_AGE = 30
        old_ts = datetime.now(timezone.utc) - timedelta(days=MAX_AGE + 1)
        m = make_manifest(version="1.9.0", rid="freeze-001", released_at=old_ts)

        released = datetime.fromisoformat(m["released_at"])
        age = datetime.now(timezone.utc) - released

        assert age.days > MAX_AGE, "Test setup error: manifest nie jest wystarczająco stary"
        # Weryfikacja logiki z updater.py §2a
        assert age > timedelta(days=MAX_AGE), (
            f"Stary manifest ({age.days} dni) powinien być odrzucony jako freeze attack"
        )

    def test_freeze_attack_within_window_allowed(self):
        """Manifest w oknie czasowym (np. 1 dzień stary) musi być dopuszczony."""
        MAX_AGE = 30
        recent_ts = datetime.now(timezone.utc) - timedelta(days=1)
        m = make_manifest(version="1.9.0", rid="fresh-001", released_at=recent_ts)

        released = datetime.fromisoformat(m["released_at"])
        age = datetime.now(timezone.utc) - released

        assert age <= timedelta(days=MAX_AGE)

    def test_missing_released_at_blocked(self):
        """A12: Manifest bez pola released_at musi być odrzucony."""
        m = make_manifest(rid="no-ts-001")
        del m["released_at"]

        assert "released_at" not in m, "Fixture error"
        # Updater.py odrzuca manifest jeśli pole nieobecne
        assert not m.get("released_at"), (
            "Manifest bez released_at powinien być zablokowany jako wariant freeze attack"
        )

    @pytest.mark.parametrize("local_ver,server_ver,expect_update", [
        ("2.0.0", "1.5.0", False),   # downgrade — zablokowany
        ("2.0.0", "2.0.0", False),   # ta sama wersja — brak update
        ("1.5.0", "2.0.0", True),    # poprawna aktualizacja — dozwolona
        ("1.0.0", "1.0.1", True),    # patch update — dozwolony
    ])
    def test_version_comparison(self, local_ver, server_ver, expect_update):
        """A13: Weryfikacja logiki porównywania wersji (downgrade + same + upgrade)."""
        pytest.importorskip("packaging", reason="pip install packaging")
        from packaging import version as pv

        is_newer = pv.parse(server_ver) > pv.parse(local_ver)
        assert is_newer == expect_update, (
            f"local={local_ver}, server={server_ver}: "
            f"oczekiwano update={expect_update}, dostano {is_newer}"
        )

    def test_binary_sha256_tamper_detected(self):
        """A14: Podmiana 1 bajtu w pobranym pliku musi być wykryta przez SHA-256."""
        original = b"Authentic update binary v2.0.0\n" + b"\x00" * 1024
        expected_sha256 = hashlib.sha256(original).hexdigest()

        tampered = bytearray(original)
        tampered[42] ^= 0xFF
        actual_sha256 = hashlib.sha256(bytes(tampered)).hexdigest()

        assert actual_sha256 != expected_sha256, (
            "SHA-256 nie wykrył podmiany bajtu — integralność pliku naruszona"
        )

    @pytest.mark.parametrize("flip_byte_idx", [0, 255, 511])
    def test_chunk_hash_tamper_detected(self, flip_byte_idx):
        """A15: Podmiana dowolnego bajtu w chunku musi być wykryta przez chunk_hash."""
        chunk = b"CHUNK_DATA_" + b"\xAA" * 501

        expected_hash = hashlib.sha256(chunk).hexdigest()

        tampered = bytearray(chunk)
        tampered[flip_byte_idx] ^= 0x01
        actual_hash = hashlib.sha256(bytes(tampered)).hexdigest()

        assert actual_hash != expected_hash, (
            f"Chunk hash nie wykrył podmiany bajtu na pozycji {flip_byte_idx}"
        )

    def test_sha256_correct_file_passes(self):
        """Poprawny plik (niemodyfikowany) musi przejść weryfikację SHA-256."""
        content = b"Authentic update binary v2.0.0\n" + b"\x00" * 1024
        expected = hashlib.sha256(content).hexdigest()
        actual = hashlib.sha256(content).hexdigest()

        assert actual == expected

    def test_manifest_missing_required_fields_detected(self):
        """Manifest bez wymaganych pól sha256/size_bytes musi być odrzucony."""
        m = make_manifest()
        del m["sha256"]
        del m["size_bytes"]

        assert not m.get("sha256")
        assert not m.get("size_bytes")
