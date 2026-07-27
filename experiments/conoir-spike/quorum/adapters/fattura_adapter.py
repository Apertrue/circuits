#!/usr/bin/env python3
"""
fattura_adapter.py -- Apertrue Quorum FatturaPA adapter.

Turns a REAL Italian e-invoice (FatturaPA XML) into the Quorum
ADAPTER-INTERFACE object that `proof_a_receivable` consumes:

  { canonical_fields: {invoice_uuid, debtor_id, amount, issue_date},
    canonical_id, canonical_id_bytes,
    obligor: { pubkey_x:[32], pubkey_y:[32], signature:[64] r||s low-s, signer_role:2 } }

Canonicalisation (identical to p1_provenance, see README/admission.sh):
  invoice_uuid = supplierVAT(CedentePrestatore IdCodice) * 1e6 + Numero
  debtor_id    = buyer CodiceFiscale (CessionarioCommittente), leading zeros dropped
  amount       = ImponibileImporto in cents (5.00 EUR -> 500)
  issue_date   = DatiGeneraliDocumento/Data -> YYYYMMDD integer

canonical_id is the Poseidon2 commitment of those four fields, computed by the
`commit_receivable` Noir circuit (proof_a's scheme).

Signing spec (Quorum standard): RAW ECDSA P-256 over the 32-byte big-endian
canonical_id used DIRECTLY as the digest -- NO sha256 wrapper. This matches
`proof_a_receivable`'s in-circuit `verify_signature(...)`.

Obligor key: the real obligor PRIVATE key is not present (only obligor_leaf.pem/.pub
exist in admission/certs). So this adapter MINTS a stand-in obligor P-256 key+cert
(reused idempotently) and raw-signs canonical_id with it. The output flags this.
The real, non-gameable obligor signer is the partner crux (SdI ricevuta / IRP IRN).
"""
import argparse, binascii, json, os, subprocess, sys, xml.etree.ElementTree as ET

HERE   = os.path.dirname(os.path.abspath(__file__))
QUORUM = os.path.dirname(HERE)
NARGO  = os.environ.get("NARGO", os.path.expanduser("~/.nargo/bin/nargo"))
KEYDIR = os.path.join(HERE, "keys")
N_P256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

def _local(tag):
    return tag.split('}', 1)[-1]  # strip XML namespace

def _find(root, *path):
    """Walk by LOCAL element names (namespace-agnostic), return first text match."""
    nodes = [root]
    for name in path:
        nxt = []
        for n in nodes:
            for c in n:
                if _local(c.tag) == name:
                    nxt.append(c)
        nodes = nxt
        if not nodes:
            return None
    return nodes[0].text.strip() if nodes[0].text else None

def parse_canonical_fields(xml_path):
    root = ET.parse(xml_path).getroot()
    hdr  = next(c for c in root if _local(c.tag) == "FatturaElettronicaHeader")
    body = next(c for c in root if _local(c.tag) == "FatturaElettronicaBody")

    supplier_vat = _find(hdr, "CedentePrestatore", "DatiAnagrafici", "IdFiscaleIVA", "IdCodice")
    debtor_cf    = _find(hdr, "CessionarioCommittente", "DatiAnagrafici", "CodiceFiscale")
    numero       = _find(body, "DatiGenerali", "DatiGeneraliDocumento", "Numero")
    data         = _find(body, "DatiGenerali", "DatiGeneraliDocumento", "Data")
    imponibile   = _find(body, "DatiBeniServizi", "DatiRiepilogo", "ImponibileImporto")
    divisa       = _find(body, "DatiGenerali", "DatiGeneraliDocumento", "Divisa")

    invoice_uuid = int(supplier_vat) * 1_000_000 + int(numero)
    debtor_id    = int(debtor_cf)                       # int() drops leading zeros
    amount       = round(float(imponibile) * 100)       # EUR -> cents
    issue_date   = int(data.replace("-", ""))           # 2014-12-18 -> 20141218

    return {
        "invoice_uuid": invoice_uuid,
        "debtor_id":    debtor_id,
        "amount":       amount,
        "issue_date":   issue_date,
        "_meta": {"supplier_vat": supplier_vat, "debtor_cf": debtor_cf,
                  "numero": numero, "issue_date_raw": data, "currency": divisa,
                  "imponibile_eur": imponibile},
    }

def compute_canonical_id(fields, salt, signer_role):
    """Run commit_receivable to get [canonical_id, anchor]. canonical_id is field 0."""
    toml = (f'invoice_uuid = "{fields["invoice_uuid"]}"\n'
            f'debtor_id    = "{fields["debtor_id"]}"\n'
            f'amount       = "{fields["amount"]}"\n'
            f'issue_date   = "{fields["issue_date"]}"\n'
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

def mint_standin_obligor():
    """Idempotently mint a stand-in obligor P-256 key + self-signed cert."""
    key = os.path.join(KEYDIR, "obligor_standin.key")
    pem = os.path.join(KEYDIR, "obligor_standin.pem")
    os.makedirs(KEYDIR, exist_ok=True)
    if not os.path.exists(key):
        subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey",
                        "-noout", "-out", key], check=True, capture_output=True)
        subprocess.run(["openssl", "req", "-new", "-x509", "-key", key, "-out", pem,
                        "-days", "3650",
                        "-subj", "/CN=obligor_standin/O=Apertrue Quorum STANDIN"],
                       check=True, capture_output=True)
    return key

def raw_sign_and_extract(key_path, cid_hex, workdir):
    """Raw-ECDSA sign the 32-byte canonical_id; return (x[32], y[32], sig r||s low-s [64])."""
    cid_bin = os.path.join(workdir, "cid.bin")
    sig_der = os.path.join(workdir, "sig.der")
    pub_der = os.path.join(workdir, "pub.der")
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

def main():
    ap = argparse.ArgumentParser(description="FatturaPA -> Quorum adapter-interface object")
    ap.add_argument("xml", nargs="?",
                    default=os.path.join(QUORUM, "p1_provenance", "IT01234567890_FPR01.xml"))
    ap.add_argument("--salt", default="42")
    ap.add_argument("--signer-role", default="2")
    ap.add_argument("--out", default=os.path.join(HERE, "fattura_adapter_object.json"))
    args = ap.parse_args()

    fields = parse_canonical_fields(args.xml)
    canonical_id, anchor = compute_canonical_id(fields, args.salt, args.signer_role)
    cid_hex = canonical_id[2:].rjust(64, "0")
    cid_bytes = list(binascii.unhexlify(cid_hex))

    key_path = mint_standin_obligor()
    workdir = os.path.join(HERE, "keys")
    x, y, sig = raw_sign_and_extract(key_path, cid_hex, workdir)

    obj = {
        "scheme": "FatturaPA",
        "source_document": os.path.basename(args.xml),
        "canonical_fields": {
            "invoice_uuid": fields["invoice_uuid"],
            "debtor_id":    fields["debtor_id"],
            "amount":       fields["amount"],
            "issue_date":   fields["issue_date"],
        },
        "canonical_id": canonical_id,
        "canonical_id_bytes": cid_bytes,
        "obligor": {
            "pubkey_x": x,
            "pubkey_y": y,
            "signature": sig,            # 64 bytes r||s, low-s normalised
            "signer_role": int(args.signer_role),
        },
        "_role_bound_anchor_at_salt": {"salt": int(args.salt), "anchor": anchor},
        "_notes": {
            "signing_spec": "raw ECDSA P-256 over be32(canonical_id) used directly as digest (no sha256)",
            "obligor_key": "STAND-IN: minted P-256 key (adapters/keys/obligor_standin.key); "
                           "real obligor key is the partner crux (SdI ricevuta / IRP IRN), not present in repo",
            "field_derivation": fields["_meta"],
        },
    }
    open(args.out, "w").write(json.dumps(obj, indent=2))
    print(json.dumps(obj, indent=2))
    print(f"\n# wrote {args.out}", file=sys.stderr)

if __name__ == "__main__":
    main()
