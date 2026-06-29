#!/usr/bin/env python3
"""
warehouse_adapter.py -- Apertrue Quorum C2PA WAREHOUSE-RECEIPT adapter.

Parallel to fattura_adapter.py, but for an UNSTRUCTURED collateral document (a
warehouse receipt) that has NO native clearance/structured rail to ride. So here
**C2PA is the load-bearing CARRIER**: the signed canonical fields + the operator's
key + the operator's raw-ECDSA signature over canonical_id are embedded in a C2PA
custom assertion and hash-bound to the document, then READ BACK out of the manifest.

It emits the SAME Quorum adapter-interface object that `proof_a_receivable` consumes:

  { canonical_fields: {receipt_uuid, commodity_id, quantity, deposit_date},
    canonical_id, canonical_id_bytes,
    obligor: { pubkey_x:[32], pubkey_y:[32], signature:[64] r||s low-s, signer_role:2 } }

Field mapping onto the (generic, 4-field) commit_receivable / proof_a circuits:
    receipt_uuid  -> slot 1 (invoice_uuid)
    commodity_id  -> slot 2 (debtor_id)
    quantity      -> slot 3 (amount)
    deposit_date  -> slot 4 (issue_date)
The circuit hashes four Fields generically, so the *names* are adapter-local.

Signing spec (Quorum standard, identical to fattura): RAW ECDSA P-256 over the
32-byte big-endian canonical_id used DIRECTLY as the digest (NO sha256 wrapper),
low-S normalised. signer_role = 2 (the non-gameable custodian/operator attestation;
reuses role 2 so bound_receivables' accepted_roles works unchanged).

Modes:
  wrap  -- mint keys, sign canonical_id, build the warehouse-receipt PDF, embed a
           C2PA `org.apertrue.quorum.collateral` custom assertion + c2pa.hash.data
           hard binding  (REQUIRES the c2pie venv python).
  read  -- parse the C2PA manifest back out (c2patool), recover {fields, pubkey,
           signature, signer_role}, re-derive canonical_id from the RECOVERED fields
           and assert it matches the embedded one, emit warehouse_adapter_object.json.
  both  -- wrap then read (default).

STAND-IN caveats (see ADAPTER.md): the warehouse-operator P-256 key is a minted
stand-in (real operator key is the partner crux); the C2PA manifest is signed by a
minted RSA leaf->CA chain (PS256). c2pie is the carrier tool. Proof A trusts the
operator LEAF key directly via the trust list, not an in-circuit X.509 chain.
"""
import argparse, base64, binascii, json, os, subprocess, sys

HERE   = os.path.dirname(os.path.abspath(__file__))
QUORUM = os.path.dirname(HERE)
NARGO  = os.environ.get("NARGO", os.path.expanduser("~/.nargo/bin/nargo"))
KEYDIR = os.path.join(HERE, "keys")
N_P256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# --- concrete warehouse-receipt canonical fields (Meridian Bonded Storage, receipt 42) ---
DEFAULT_FIELDS = {
    "receipt_uuid": 7001234000042,   # operator licence 7001234 * 1e6 + receipt no 42
    "commodity_id": 74031100,        # HS code: copper cathode, grade A
    "quantity":     25000,           # 250.00 metric tonnes, in centi-tonnes
    "deposit_date": 20240315,        # 2024-03-15
}
RECEIPT_PDF = os.path.join(HERE, "warehouse_receipt.pdf")
C2PA_PDF    = os.path.join(HERE, "warehouse_receipt_c2pa.pdf")
COLLATERAL_LABEL = "org.apertrue.quorum.collateral"


# --------------------------------------------------------------------------- #
# circuit helpers (shared with fattura adapter)
# --------------------------------------------------------------------------- #
def compute_canonical_id(fields, salt, signer_role):
    """Run commit_receivable to get [canonical_id, anchor]. canonical_id is field 0."""
    toml = (f'invoice_uuid = "{fields["receipt_uuid"]}"\n'
            f'debtor_id    = "{fields["commodity_id"]}"\n'
            f'amount       = "{fields["quantity"]}"\n'
            f'issue_date   = "{fields["deposit_date"]}"\n'
            f'salt         = "{salt}"\n'
            f'signer_role  = "{signer_role}"\n')
    cr = os.path.join(QUORUM, "commit_receivable")
    open(os.path.join(cr, "Prover.toml"), "w").write(toml)
    out = subprocess.run([NARGO, "execute", "--program-dir", cr],
                         capture_output=True, text=True).stdout
    line = next(l for l in out.splitlines() if "Circuit output" in l)
    inner = line.split("Circuit output:", 1)[1].split("[", 1)[1].rsplit("]", 1)[0]
    cid, anchor = [t.strip() for t in inner.split(",")]
    return cid, anchor


def mint_standin_operator():
    """Idempotently mint a stand-in warehouse-operator P-256 key + self-signed cert."""
    key = os.path.join(KEYDIR, "operator_standin.key")
    pem = os.path.join(KEYDIR, "operator_standin.pem")
    os.makedirs(KEYDIR, exist_ok=True)
    if not os.path.exists(key):
        subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey",
                        "-noout", "-out", key], check=True, capture_output=True)
        subprocess.run(["openssl", "req", "-new", "-x509", "-key", key, "-out", pem,
                        "-days", "3650",
                        "-subj", "/CN=warehouse_operator_standin/O=Apertrue Quorum STANDIN"],
                       check=True, capture_output=True)
    return key


def mint_c2pa_rsa_chain():
    """Idempotently mint an RSA CA->leaf chain (PS256, emailProtection EKU) for the
    C2PA manifest signer. Returns (leaf_pkcs8_key_path, chain_pem_path)."""
    os.makedirs(KEYDIR, exist_ok=True)
    ca_key  = os.path.join(KEYDIR, "c2pa_ca.key")
    ca_pem  = os.path.join(KEYDIR, "c2pa_ca.pem")
    leaf_t  = os.path.join(KEYDIR, "c2pa_leaf_trad.key")
    leaf_k  = os.path.join(KEYDIR, "c2pa_leaf.key")     # PKCS#8 (what c2pie wants)
    leaf_p  = os.path.join(KEYDIR, "c2pa_leaf.pem")     # = chain (leaf only, no root)
    csr     = os.path.join(KEYDIR, "c2pa_leaf.csr")
    ext     = os.path.join(KEYDIR, "c2pa_leaf.ext")
    if not os.path.exists(leaf_k):
        run = lambda *a: subprocess.run(a, check=True, capture_output=True)
        run("openssl", "genrsa", "-out", ca_key, "3072")
        run("openssl", "req", "-new", "-x509", "-key", ca_key, "-out", ca_pem, "-days", "3650",
            "-subj", "/CN=apertrue_quorum_c2pa_ca/O=Apertrue Quorum STANDIN",
            "-addext", "basicConstraints=critical,CA:TRUE")
        run("openssl", "genrsa", "-out", leaf_t, "3072")
        run("openssl", "pkcs8", "-topk8", "-nocrypt", "-in", leaf_t, "-out", leaf_k)
        run("openssl", "req", "-new", "-key", leaf_k, "-out", csr,
            "-subj", "/CN=apertrue_quorum_c2pa_leaf/O=Apertrue Quorum STANDIN")
        open(ext, "w").write("keyUsage=critical,digitalSignature\nextendedKeyUsage=emailProtection\n")
        run("openssl", "x509", "-req", "-in", csr, "-CA", ca_pem, "-CAkey", ca_key,
            "-CAcreateserial", "-out", leaf_p, "-days", "3650", "-extfile", ext)
    return leaf_k, leaf_p


def raw_sign_and_extract(key_path, cid_hex, workdir):
    """Raw-ECDSA sign the 32-byte canonical_id; return (x[32], y[32], sig r||s low-s [64])."""
    cid_bin = os.path.join(workdir, "wh_cid.bin")
    sig_der = os.path.join(workdir, "wh_sig.der")
    pub_der = os.path.join(workdir, "wh_pub.der")
    open(cid_bin, "wb").write(binascii.unhexlify(cid_hex))
    # pkeyutl -sign treats the EC input bytes AS the digest -> raw ECDSA, no sha256 wrapper
    subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", key_path,
                    "-in", cid_bin, "-out", sig_der], check=True, capture_output=True)
    subprocess.run(["openssl", "ec", "-in", key_path, "-pubout",
                    "-conv_form", "uncompressed", "-outform", "DER", "-out", pub_der],
                   check=True, capture_output=True)
    pub = open(pub_der, "rb").read()
    point = pub[-65:]
    assert point[0] == 4, "public key is not an uncompressed point"
    x = list(point[1:33]); y = list(point[33:65])
    der = open(sig_der, "rb").read()
    assert der[0] == 0x30
    def read_int(b, i):
        assert b[i] == 0x02
        ln = b[i + 1]
        return b[i + 2:i + 2 + ln], i + 2 + ln
    r, i = read_int(der, 2)
    s, _ = read_int(der, i)
    sv = int.from_bytes(s, "big")
    if sv > N_P256 // 2:           # Noir verify_signature requires LOW-S (canonical)
        sv = N_P256 - sv
    s = sv.to_bytes(32, "big")
    r = r.lstrip(b"\x00").rjust(32, b"\x00")
    sig = list(r) + list(s)
    return x, y, sig


# --------------------------------------------------------------------------- #
# the warehouse-receipt document
# --------------------------------------------------------------------------- #
def build_receipt_pdf(fields, out_pdf):
    """Render a simple warehouse-receipt text -> PDF via cupsfilter (idempotent)."""
    qty = fields["quantity"] / 100.0
    d   = str(fields["deposit_date"])
    txt = f"""WAREHOUSE RECEIPT (NON-NEGOTIABLE)

Operator      : Meridian Bonded Storage Ltd  (licence 7001234)
Receipt UUID  : {fields['receipt_uuid']}
Commodity     : Copper Cathode, Grade A  (HS {fields['commodity_id']})
Quantity      : {qty:.2f} metric tonnes
Deposit date  : {d[0:4]}-{d[4:6]}-{d[6:8]}
Location      : Bonded Warehouse 7, Rotterdam

This receipt evidences collateral held on deposit and is the carrier for the
Apertrue Quorum custodian attestation embedded as a C2PA assertion in this file.
"""
    txt_path = os.path.join(HERE, "warehouse_receipt.txt")
    open(txt_path, "w").write(txt)
    raw = subprocess.run(["/usr/sbin/cupsfilter", txt_path],
                         check=True, capture_output=True).stdout
    open(out_pdf, "wb").write(raw)
    return out_pdf


# --------------------------------------------------------------------------- #
# WRAP: embed the signed canonical fields into a C2PA custom assertion
# --------------------------------------------------------------------------- #
def wrap(fields, salt, signer_role):
    import hashlib
    from c2pie.interface import (c2pie_GenerateHashDataAssertion,
                                 c2pie_GenerateManifest, c2pie_EmplaceManifest)
    from c2pie.utils.assertion_schemas import json_to_bytes, C2PA_AssertionTypes
    from c2pie.utils.content_types import C2PA_ContentTypes, jumbf_content_types
    from c2pie.jumbf_boxes.super_box import SuperBox
    from c2pie.jumbf_boxes.content_box import ContentBox

    class CustomJsonAssertion(SuperBox):
        """C2PA assertion with an arbitrary label + JSON payload (c2pie ships only 3 enum types)."""
        def __init__(self, label, schema):
            self.type = C2PA_AssertionTypes.creative_work  # any value != data_hash
            self.schema = schema
            cb = ContentBox(box_type=b"json".hex(), payload=json_to_bytes(schema))
            super().__init__(content_type=jumbf_content_types["json"], label=label,
                             content_boxes=[cb])
        def get_data_for_signing(self):
            return self.description_box.serialize() + self.serialize_content_boxes()

    canonical_id, anchor = compute_canonical_id(fields, salt, signer_role)
    cid_hex = canonical_id[2:].rjust(64, "0")

    op_key = mint_standin_operator()
    x, y, sig = raw_sign_and_extract(op_key, cid_hex, KEYDIR)

    build_receipt_pdf(fields, RECEIPT_PDF)
    raw = open(RECEIPT_PDF, "rb").read()

    # The collateral assertion IS the rail: it carries the signed canonical fields,
    # the operator's pubkey (x,y) and the raw-ECDSA signature over canonical_id.
    collateral = {
        "scheme": "WarehouseReceipt",
        "signer_role": signer_role,
        "signer_role_name": "warehouse-operator / custodian attestation",
        "guarantee": "the collateral is genuinely on deposit",
        "non_gameable_signer": "Meridian Bonded Storage Ltd (operator) [STAND-IN CERT]",
        "canonical_fields": {
            "receipt_uuid": fields["receipt_uuid"],
            "commodity_id": fields["commodity_id"],
            "quantity":     fields["quantity"],
            "deposit_date": fields["deposit_date"],
        },
        "canonical_id": canonical_id,
        "anchor": anchor,
        "salt": salt,
        # the operator's P-256 attestation over canonical_id (the load-bearing TRUST)
        "operator_pubkey_x_hex": "".join(f"{b:02x}" for b in x),
        "operator_pubkey_y_hex": "".join(f"{b:02x}" for b in y),
        "signature_rs_low_s_hex": "".join(f"{b:02x}" for b in sig),
        "signing_spec": "raw ECDSA P-256 over be32(canonical_id) used directly as digest (no sha256), low-s",
        "source_document": "warehouse_receipt.pdf (this file)",
    }
    collateral_assertion = CustomJsonAssertion(COLLATERAL_LABEL, collateral)

    # hard binding over the WHOLE pdf; manifest appended at EOF
    cai_offset = len(raw)
    hash_data = c2pie_GenerateHashDataAssertion(cai_offset=cai_offset,
                                                hashed_data=hashlib.sha256(raw).digest())
    manifest = c2pie_GenerateManifest(
        assertions=[collateral_assertion, hash_data],
        private_key=open(mint_c2pa_rsa_chain()[0], "rb").read(),
        certificate_chain=open(mint_c2pa_rsa_chain()[1], "rb").read(),
    )
    signed = c2pie_EmplaceManifest(C2PA_ContentTypes.pdf, raw, cai_offset, manifest)
    open(C2PA_PDF, "wb").write(signed)
    print(f"# wrap: signed C2PA warehouse receipt -> {C2PA_PDF} ({len(signed)} bytes)",
          file=sys.stderr)
    return C2PA_PDF


# --------------------------------------------------------------------------- #
# READ: pull the assertion back out of the C2PA manifest (c2patool)
# --------------------------------------------------------------------------- #
def read_manifest(pdf_path):
    """Parse the C2PA manifest via c2patool, return (collateral_assertion_dict, manifest_label)."""
    out = subprocess.run(["c2patool", pdf_path], check=True, capture_output=True, text=True).stdout
    rep = json.loads(out)
    label = rep["active_manifest"]
    man = rep["manifests"][label]
    for a in man["assertions"]:
        if a["label"] == COLLATERAL_LABEL:
            return a["data"], label
    raise SystemExit(f"FAIL: {COLLATERAL_LABEL} assertion not found in {pdf_path}")


def read_and_emit(pdf_path, salt, signer_role, out_path):
    coll, manifest_label = read_manifest(pdf_path)
    f = coll["canonical_fields"]
    fields = {
        "receipt_uuid": int(f["receipt_uuid"]),
        "commodity_id": int(f["commodity_id"]),
        "quantity":     int(f["quantity"]),
        "deposit_date": int(f["deposit_date"]),
    }
    # Re-derive canonical_id from the RECOVERED fields -> must match the embedded value.
    cid_recomputed, anchor_recomputed = compute_canonical_id(fields, salt, signer_role)
    if cid_recomputed != coll["canonical_id"]:
        raise SystemExit(f"FAIL: recomputed canonical_id {cid_recomputed} != "
                         f"embedded {coll['canonical_id']}")
    print(f"# read: canonical_id from C2PA matches recompute ({cid_recomputed})", file=sys.stderr)

    cid_hex = cid_recomputed[2:].rjust(64, "0")
    cid_bytes = list(binascii.unhexlify(cid_hex))
    x = list(binascii.unhexlify(coll["operator_pubkey_x_hex"]))
    y = list(binascii.unhexlify(coll["operator_pubkey_y_hex"]))
    sig = list(binascii.unhexlify(coll["signature_rs_low_s_hex"]))
    assert len(x) == 32 and len(y) == 32 and len(sig) == 64, "bad recovered key/sig lengths"

    obj = {
        "scheme": "WarehouseReceipt",
        "source_document": os.path.basename(pdf_path),
        "carrier": "C2PA custom assertion (org.apertrue.quorum.collateral), hash-bound to the PDF",
        "c2pa_manifest_label": manifest_label,
        "canonical_fields": fields,
        "canonical_id": cid_recomputed,
        "canonical_id_bytes": cid_bytes,
        "obligor": {
            "pubkey_x": x,
            "pubkey_y": y,
            "signature": sig,            # 64 bytes r||s, low-s normalised
            "signer_role": int(signer_role),
        },
        "_role_bound_anchor_at_salt": {"salt": int(salt), "anchor": anchor_recomputed},
        "_notes": {
            "signing_spec": "raw ECDSA P-256 over be32(canonical_id) used directly as digest (no sha256)",
            "carrier_note": "C2PA is the load-bearing CARRIER: the operator key+signature are "
                            "transported in a C2PA custom assertion and hash-bound to the file; "
                            "trust is the SIGNATURE, verified in-circuit by Proof A.",
            "operator_key": "STAND-IN: minted P-256 key (adapters/keys/operator_standin.key); "
                            "real warehouse-operator key is the partner crux, not present in repo",
            "c2pa_manifest_signer": "STAND-IN RSA leaf->CA chain (adapters/keys/c2pa_leaf.*), PS256",
            "field_mapping": "receipt_uuid->slot1, commodity_id->slot2, quantity->slot3, deposit_date->slot4",
        },
    }
    open(out_path, "w").write(json.dumps(obj, indent=2))
    print(json.dumps(obj, indent=2))
    print(f"\n# wrote {out_path}", file=sys.stderr)
    return obj


def main():
    ap = argparse.ArgumentParser(description="C2PA warehouse receipt -> Quorum adapter-interface object")
    ap.add_argument("--mode", choices=["wrap", "read", "both"], default="both")
    ap.add_argument("--salt", default="42")
    ap.add_argument("--signer-role", default="2")
    ap.add_argument("--pdf", default=C2PA_PDF, help="C2PA pdf to read (read mode)")
    ap.add_argument("--out", default=os.path.join(HERE, "warehouse_adapter_object.json"))
    args = ap.parse_args()
    fields = dict(DEFAULT_FIELDS)

    if args.mode in ("wrap", "both"):
        wrap(fields, args.salt, args.signer_role)
    if args.mode in ("read", "both"):
        read_and_emit(args.pdf, args.salt, args.signer_role, args.out)


if __name__ == "__main__":
    main()
