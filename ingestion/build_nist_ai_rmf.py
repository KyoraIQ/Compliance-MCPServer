"""
Build NIST AI RMF 1.0 into the Kyora IQ schema at full depth.

Verified structure (NIST AI 100-1, Jan 2023):
  4 functions, 19 categories, 72 subcategories.
  GOVERN: 6 categories (19 subcategories)
  MAP:    5 categories (18 subcategories)
  MEASURE:4 categories (22 subcategories)
  MANAGE: 4 categories (13 subcategories)

Source handling: PARAPHRASED / public domain. NIST text is public domain; we
carry the functions and 19 categories with our own short summaries. Subcategory
counts are noted in each category summary so the depth is represented honestly
without reproducing all 72 verbatim.
"""
import json, sys, datetime

# function_code, function_name, [(cat_code, cat_name, n_subs, layer, summary)]
FUNCTIONS = [
    ("GOVERN", "Govern", [
        ("GOVERN 1", "Policies, Processes, Procedures, and Practices", 7, "governance",
         "Policies and processes for AI risk management are in place, transparent, and implemented across the organization, including legal and regulatory understanding."),
        ("GOVERN 2", "Accountability Structures", 3, "governance",
         "Accountability structures are in place so the right teams and individuals are empowered, responsible, and trained for AI risk management."),
        ("GOVERN 3", "Workforce Diversity and Inclusion", 2, "governance",
         "Workforce diversity, equity, inclusion, and accessibility are prioritized in the mapping, measuring, and managing of AI risk."),
        ("GOVERN 4", "Organizational Culture and Critical Thinking", 3, "governance",
         "Organizational teams are committed to a culture that considers and communicates AI risk, encouraging critical thinking and safety-first mindsets."),
        ("GOVERN 5", "Stakeholder Engagement", 2, "governance",
         "Processes are in place for robust engagement with relevant AI actors and affected communities, including mechanisms to collect and act on feedback."),
        ("GOVERN 6", "Third-Party Risk", 2, "governance",
         "Policies address the risks and benefits of third-party AI software, data, and supply-chain components, including how they are acquired and monitored."),
    ]),
    ("MAP", "Map", [
        ("MAP 1", "Context Establishment", 6, "governance",
         "The context in which the AI system operates is established and understood, including intended purpose, settings, norms, and the organization's mission."),
        ("MAP 2", "Categorization", 3, "model",
         "The AI system, its capabilities, the tasks it performs, and the methods used are categorized and documented."),
        ("MAP 3", "AI Capabilities, Targeted Usage, Goals", 5, "model",
         "The system's capabilities, targeted usage, goals, and expected benefits and costs are understood relative to appropriate benchmarks."),
        ("MAP 4", "Risk and Benefit Mapping of Third Parties", 2, "governance",
         "Risks and benefits are mapped for all components of the AI system, including third-party software, data, and the broader value chain."),
        ("MAP 5", "Impacts on Individuals, Groups, and Society", 2, "output",
         "Impacts to individuals, groups, communities, organizations, and society are characterized, including the likelihood and magnitude of each identified impact."),
    ]),
    ("MEASURE", "Measure", [
        ("MEASURE 1", "Appropriate Methods and Metrics", 3, "model",
         "Appropriate methods and metrics are identified and applied to measure the AI risks enumerated during the Map function."),
        ("MEASURE 2", "Trustworthiness Evaluation", 13, "model",
         "AI systems are evaluated for trustworthy characteristics including validity, reliability, safety, security, resilience, privacy, fairness, bias, transparency, and explainability."),
        ("MEASURE 3", "Risk Tracking Mechanisms", 3, "infrastructure",
         "Mechanisms for tracking identified AI risks over time are in place, including for risks that are difficult to measure and emergent risks."),
        ("MEASURE 4", "Measurement Effectiveness", 3, "governance",
         "Feedback about the efficacy of measurement is gathered and assessed, including input from domain experts and affected users."),
    ]),
    ("MANAGE", "Manage", [
        ("MANAGE 1", "Risk Prioritization and Response", 4, "agentic",
         "AI risks based on assessments and other analytical output are prioritized, responded to, and managed, including decisions to proceed or not."),
        ("MANAGE 2", "Sustained Value and Risk Treatment", 4, "agentic",
         "Strategies to maximize AI benefits and minimize negative impacts are planned, prepared, implemented, documented, and communicated."),
        ("MANAGE 3", "Third-Party Risk Management", 2, "governance",
         "AI risks and benefits from third-party entities are managed, including monitoring, contingency, and override mechanisms."),
        ("MANAGE 4", "Risk Monitoring and Communication", 3, "infrastructure",
         "Risk treatments, including response and recovery and post-deployment monitoring, are documented and regularly monitored, with appeal, override, and decommissioning mechanisms."),
    ]),
]

DISCLAIMER = ("NIST AI RMF 1.0 is voluntary U.S. government guidance in the public domain. "
              "Carried at the Function and Category level with Kyora IQ summaries; the official "
              "72 subcategories are in NIST AI 100-1. Not legal advice.")

def node(cid, disp, title, layer, statement, kind, attrs=None, children=None):
    return {"id": cid, "display_id": disp, "title": title, "layer": layer,
            "statement": statement, "guidance": "", "kind": kind,
            "attributes": attrs or {}, "children": children or [], "mappings": []}

def build():
    controls = []
    total_subs = 0
    for fcode, fname, cats in FUNCTIONS:
        children = []
        for ccode, cname, n_subs, layer, summary in cats:
            total_subs += n_subs
            cid = ccode.lower().replace(" ", "-")
            full = f"{summary} ({n_subs} subcategories in NIST AI 100-1.)"
            children.append(node(cid, ccode, cname, layer, full, kind="control",
                                  attrs={"subcategories": n_subs}))
        fid = fcode.lower()
        controls.append(node(fid, fcode, fname, "governance",
                             f"{fname} function of the NIST AI Risk Management Framework.",
                             kind="function", children=children))
    data = {
        "framework": {
            "id": "nist-ai-rmf", "name": "NIST AI Risk Management Framework",
            "version": "1.0", "publisher": "NIST",
            "source_url": "https://www.nist.gov/itl/ai-risk-management-framework",
            "source_handling": "paraphrased",
            "license": "Public Domain (U.S. Government work)",
            "retrieved_at": datetime.date.today().isoformat(),
            "disclaimer": DISCLAIMER,
        },
        "controls": controls,
    }
    return data, total_subs

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "data/normalized/nist-ai-rmf.json"
    data, subs = build()
    n_cat = sum(len(f["children"]) for f in data["controls"])
    open(out, "w").write(json.dumps(data, indent=2))
    print(f"wrote {out}  ({len(data['controls'])} functions, {n_cat} categories, {subs} subcategories noted)")
