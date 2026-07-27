#!/usr/bin/env python3
"""
Apertrue Quorum P1.next -- a REAL C2PA-signed invoice PDF that:
  1. embeds the authoritative FatturaPA XML inside the PDF (so it travels under the binding),
  2. carries a custom `org.apertrue.quorum.receivable` assertion with the canonical fields,
     the role-bound anchor, and the inner non-fraudster (obligor) signature, and
  3. has a c2pa.hash.data hard binding over the whole PDF (including the embedded XML).

Run inside the c2pie venv. Inputs (real, from earlier steps):
  - invoice.pdf                         (rendered invoice)
  - IT01234567890_FPR01.xml             (real FatturaPA source)
  - admission/certs/obligor_true.sig    (real ES256 obligor signature over canonical_id)
  - rsa_leaf.key / rsa_chain.pem        (C2PA manifest signer; stand-in)
"""
import base64, hashlib, json, os, sys
from pypdf import PdfReader, PdfWriter

from c2pie.interface import (
    c2pie_GenerateAssertion, c2pie_GenerateHashDataAssertion,
    c2pie_GenerateManifest, c2pie_EmplaceManifest,
)
from c2pie.utils.assertion_schemas import C2PA_AssertionTypes, json_to_bytes
from c2pie.utils.content_types import C2PA_ContentTypes, jumbf_content_types
from c2pie.jumbf_boxes.super_box import SuperBox
from c2pie.jumbf_boxes.content_box import ContentBox

HERE = os.path.dirname(os.path.abspath(__file__))
SC   = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(HERE)))))  # unused
ADM  = os.path.join(HERE, "admission", "certs")

# real values from earlier steps (obligor variant, true receivable)
CANONICAL_ID = "0x06cc60c66ce6389ea53783b55dc5ff1b480e9a43ecf4c942262f5d73d7a87280"
ANCHOR       = "0x276218a3095f1f2a85ee95ceeece1963fb83fbbc4da888208d85b2b3013822e5"
SIGNER_ROLE  = 2  # obligor / debtor confirmation

class CustomJsonAssertion(SuperBox):
    """A C2PA assertion with an arbitrary label + JSON payload (c2pie only ships 3 enum types)."""
    def __init__(self, label: str, schema: dict):
        self.type = C2PA_AssertionTypes.creative_work  # any value != data_hash
        self.schema = schema
        content_box = ContentBox(box_type=b"json".hex(), payload=json_to_bytes(schema))
        super().__init__(content_type=jumbf_content_types["json"], label=label, content_boxes=[content_box])
    def get_data_for_signing(self) -> bytes:
        return self.description_box.serialize() + self.serialize_content_boxes()

def main():
    invoice_pdf = os.path.join(HERE, "invoice.pdf")
    xml_path    = os.path.join(HERE, "IT01234567890_FPR01.xml")
    key_path    = sys.argv[1]   # rsa_leaf.key
    chain_path  = sys.argv[2]   # rsa_chain.pem
    out_path    = os.path.join(HERE, "invoice_quorum.pdf")

    # --- 1) embed the authoritative FatturaPA XML INSIDE the PDF ---
    xml_bytes = open(xml_path, "rb").read()
    r = PdfReader(invoice_pdf); w = PdfWriter(); w.append(r)
    w.add_attachment("IT01234567890_FPR01.xml", xml_bytes)
    tmp = os.path.join(HERE, "invoice_with_xml.pdf")
    with open(tmp, "wb") as f: w.write(f)
    raw = open(tmp, "rb").read()
    print("embedded XML -> PDF: %d bytes (orig invoice %d, xml %d)" % (len(raw), os.path.getsize(invoice_pdf), len(xml_bytes)))

    # --- 2) custom receivable assertion carrying fields + role-bound anchor + inner signature ---
    obligor_sig_b64 = base64.b64encode(open(os.path.join(ADM, "obligor_true.sig"), "rb").read()).decode()
    receivable = {
        "scheme": "FatturaPA",
        "signer_role": SIGNER_ROLE,
        "signer_role_name": "obligor/debtor confirmation",
        "guarantee": "the debt is genuinely owed",
        "non_fraudster_signer": "DITTA BETA (debtor) [STAND-IN CERT]",
        "supplier_vat": "IT01234567890",
        "debtor_cf": "09876543210",
        "invoice_number": "123",
        "issue_date": "2014-12-18",
        "amount_cents": 500,
        "currency": "EUR",
        "canonical_id": CANONICAL_ID,
        "anchor": ANCHOR,
        "inner_signature_es256_over_canonical_id_b64": obligor_sig_b64,
        "source_document": "IT01234567890_FPR01.xml (embedded in this PDF)",
    }
    receivable_assertion = CustomJsonAssertion("org.apertrue.quorum.receivable", receivable)

    # carry the AUTHORITATIVE source XML inside the signed manifest itself, so it travels with
    # the C2PA (bound by the claim signature, extractable regardless of PDF attachment quirks).
    source_doc = {
        "format": "application/xml (FatturaPA)",
        "filename": "IT01234567890_FPR01.xml",
        "sha256": hashlib.sha256(xml_bytes).hexdigest(),
        "bytes_b64": base64.b64encode(xml_bytes).decode(),
    }
    source_assertion = CustomJsonAssertion("org.apertrue.quorum.source_document", source_doc)
    creative_work = c2pie_GenerateAssertion(C2PA_AssertionTypes.creative_work, {
        "@context": "https://schema.org", "@type": "CreativeWork",
        "author": [{"@type": "Organization", "name": "IT-SdI / debtor confirmation STAND-IN"}],
        "copyrightYear": "2014", "copyrightHolder": "FatturaPA no.123",
    })

    # --- 3) hard binding over the WHOLE pdf (incl. embedded XML); manifest appended at EOF ---
    cai_offset = len(raw)
    hash_data = c2pie_GenerateHashDataAssertion(cai_offset=cai_offset, hashed_data=hashlib.sha256(raw).digest())

    manifest = c2pie_GenerateManifest(
        assertions=[receivable_assertion, source_assertion, creative_work, hash_data],
        private_key=open(key_path, "rb").read(),
        certificate_chain=open(chain_path, "rb").read(),
    )
    signed = c2pie_EmplaceManifest(C2PA_ContentTypes.pdf, raw, cai_offset, manifest)
    with open(out_path, "wb") as f: f.write(signed)
    print("signed C2PA PDF -> %s (%d bytes)" % (out_path, len(signed)))

if __name__ == "__main__":
    main()
