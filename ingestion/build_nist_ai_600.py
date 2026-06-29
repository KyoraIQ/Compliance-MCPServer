"""
Build NIST AI 600-1 Generative AI Profile into the Kyora IQ schema at full depth.

Verified structure (NIST AI 600-1, July 2024): 12 GenAI risk categories, each
mapped to suggested actions across the four AI RMF functions.

Source handling: PARAPHRASED / public domain. We carry all 12 risk categories
with our own short summaries.

NOTE: existing cross-framework mappings reference ga-2-7, ga-2-8, ga-2-9,
ga-2-12. Those IDs are preserved here so mappings keep resolving.
"""
import json, sys, datetime

# (id, display, title, layer, summary)
# NOTE: ga-2-7 (Data Privacy), ga-2-8 (Confabulation/Integrity), ga-2-9
# (Information Security), ga-2-12 (Value Chain) keep their original meanings
# because existing cross-framework mappings reference them.
RISKS = [
    ("ga-2-1", "GAI 2.1", "CBRN Information or Capabilities", "governance",
     "Risk that generative AI lowers the barrier to access or synthesize harmful chemical, biological, radiological, or nuclear information or capabilities."),
    ("ga-2-2", "GAI 2.2", "Confabulation", "output",
     "Risk that the system produces confidently stated false or fabricated content (also called hallucination) that users may over-trust."),
    ("ga-2-3", "GAI 2.3", "Dangerous, Violent, or Hateful Content", "output",
     "Risk that the system produces or eases production of dangerous, violent, or hateful content, including incitement and recommendations for self-harm."),
    ("ga-2-4", "GAI 2.4", "Environmental Impacts", "infrastructure",
     "Risk from the high compute, energy, and water demands of training and operating large generative AI models."),
    ("ga-2-5", "GAI 2.5", "Harmful Bias and Homogenization", "model",
     "Risk that the system amplifies harmful bias, discriminates, or homogenizes outputs in ways that disadvantage groups of people."),
    ("ga-2-6", "GAI 2.6", "Human-AI Configuration", "agentic",
     "Risk from how humans and the AI system interact, including over-reliance, automation bias, misuse, and unclear roles in decision-making."),
    ("ga-2-7", "GAI 2.7", "Data Privacy", "output",
     "Risk that generative AI leaks, infers, or reconstructs sensitive personal data from training data, context, or other users."),
    ("ga-2-8", "GAI 2.8", "Information Integrity", "output",
     "Risk that generative AI degrades information integrity at scale, including confabulation, misinformation, disinformation, and deceptive synthetic content."),
    ("ga-2-9", "GAI 2.9", "Information Security", "input",
     "Risk to information security from generative AI, including prompt injection, data poisoning, model theft, and expanded attack surface."),
    ("ga-2-10", "GAI 2.10", "Intellectual Property", "output",
     "Risk that the system reproduces or infringes copyrighted, trademarked, or licensed material, or leaks proprietary training data."),
    ("ga-2-11", "GAI 2.11", "Obscene, Degrading, or Abusive Content", "output",
     "Risk that the system generates obscene, degrading, or non-consensual intimate content, including synthetic CSAM and abusive imagery."),
    ("ga-2-12", "GAI 2.12", "Value Chain and Component Integration", "model",
     "Risk arising from third-party models, data, and components integrated into the generative AI value chain, including opaque provenance."),
]

DISCLAIMER = ("NIST AI 600-1 Generative AI Profile is voluntary U.S. government guidance in the "
              "public domain. The 12 risk categories are carried with Kyora IQ summaries; see the "
              "official publication for full text and suggested actions. Not legal advice.")

def node(cid, disp, title, layer, statement):
    return {"id": cid, "display_id": disp, "title": title, "layer": layer,
            "statement": statement, "guidance": "", "kind": "risk",
            "attributes": {}, "children": [], "mappings": []}

def build():
    controls = [node(*r) for r in RISKS]
    return {
        "framework": {
            "id": "nist-ai-600-1", "name": "NIST AI 600-1 Generative AI Profile",
            "version": "600-1", "publisher": "NIST",
            "source_url": "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf",
            "source_handling": "paraphrased",
            "license": "Public Domain (U.S. Government work)",
            "retrieved_at": datetime.date.today().isoformat(),
            "disclaimer": DISCLAIMER,
        },
        "controls": controls,
    }

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "data/normalized/nist-ai-600-1.json"
    data = build()
    open(out, "w").write(json.dumps(data, indent=2, ensure_ascii=False))
    print(f"wrote {out}  ({len(data['controls'])} risk categories)")
