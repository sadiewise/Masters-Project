import streamlit as st
import pandas as pd
import plotly.express as px
import matplotlib.pyplot as plt
import streamlit.components.v1 as components
from pathlib import Path
from io import BytesIO
from PIL import Image
from typing import Optional, Union 


st.title("Ethical Cybersecurity Dashboard to Aid Policy Making and Cyber Deterrence Strategies In the UK")
st.markdown("21019207 - MSc Data Science - CSCT Masters Project")

st.set_page_config(page_title="Cyber Policy Dashboard", layout="wide")

st.set_page_config(page_title="Ethical Cyber Policy Studio", layout="wide")

st.title("Key Statistics")

c1, c2, c3 = st.columns(3)
c1.metric("NCSC IM incidents (2024)", "430")    
c2.metric("Nationally significant (2024)", "89")
c3.metric("Business breach prevalence (2025)", "43%")

st.subheader("This dashboard aims to aid you in upholding ethical practice in policy making in the everchanging technology sector.")
st.subheader("So why does ethical cyber deterrance matter?")
st.markdown(" Ethical cyber deterrance matters because it's the difference between protecting digital societies responsibly and spiralling into a lawless arms race."\
            "Ethical cyber detterance preserves global stability, builds trust among nations, reduces collateral damage, and sets norms for future conflicts. " \
            "When it comes to the UK, the conversation is deeply routed in how the nation balances power, legality, and demoncratic values in cyberspace." \
            "The UKs approach to cyber deterrance, especially through its National Cyber Force (NCF), has sparked a range of ethical debates. These discussions" \
            " revolve around how the UK balances national security with democratic values, legal boundaries, and global norms.")


# --- Session state defaults ---
st.session_state.setdefault("show_dashboard", False)
st.session_state.setdefault("intent", "Prevention")
st.session_state.setdefault("scale", 5)



# --- Helper: policy evaluator ---
def evaluate_policy(scale: int, simintent: str):
    if scale >= 8:
        severity = "High"
    elif scale >= 5:
        severity = "Moderate"
    else:
        severity = "Low"

    if intent == "Prevention":
        advice = (
            "**Focus on threat reduction and system hardening.**\n\n"
            "- Use proactive risk scanning and patch management, Intrusion Prevention System (IPS).\n"
            "- Align with https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf.\n"
            "- Consider UK’s [Active Cyber Defence](https://www.ncsc.gov.uk/collection/risk-management) strategy.\n\n"
            "**Case Studies and lessons learnt**\n\n"
            "- MoD Contractor Data Breach (August 2025) - https://www.theguardian.com/uk-news/2025/aug/16/cyber-attack-on-mod-linked-contractor-exposes-data-of-afghans-in-resettlement-scheme?utm_source=chatgpt.com \n"
            "- British Library Ransomware attack (2023) - https://www.computerweekly.com/feature/British-Library-cyber-attack-explained-What-you-need-to-know \n\n"
            "**Lessons learnt across cases include:**\n\n"
            "- Third-party risk is significant—many breaches stem from weak links in supplier or contractor infrastructures.\n"
            "- Human error and poor hygiene matter—weak passwords, unpatched systems, and legacy infrastructure continue to be exploited.\n"
            "- Operational and reputational costs far outweigh immediate losses, often impacting jobs, trust, and long-term resilience.\n"
            "- Regulatory consequences are substantial, with repeated fines and legal scrutiny underscoring the need for robust data governance.\n")

    elif intent == "Detection":
        advice = (
            "**Invest in real-time monitoring and anomaly detection.**\n\n"
            "- Deploy Intrusion Detection System – https://www.geeksforgeeks.org/ethical-hacking/intrusion-detection-system-ids/.\n"
            "- Refer to https://www.ncsc.gov.uk/collection/cyber-assessment-framework/caf-objective-c-detecting-cyber-security-events\n"
            "- Map to NIST 'Detect' functions https://www.infosecinstitute.com/resources/nist-csf/nist-csf-core-functions-detect/"
        )
    elif intent == "Mitigation":
        advice = (
            "**Prepare for containment and recovery.**\n\n"
            "- Follow NCSC Incident Management: https://www.ncsc.gov.uk/section/respond-recover/medium-large\n"
            "- https://www.ncsc.gov.uk/section/advice-guidance/all-topics?topics=Mitigation&sort=date%2Bdesc\n"
            "- Conduct tabletop exercises and scenario rehearsals.\n"
            "- Ensure continuity via backup and restoration plans.\n\n"
            "**Case Studies and lessons learnt**\n\n"
            "- Marks and Spencer Ransomware attack (April- August 2025) - https://www.bbc.co.uk/news/articles/c0el31nqnpvo \n"
            "- British Airways Data Breach (2018) - https://www.bbc.co.uk/news/technology-45446529 \n\n"
            "**Lessons learnt across cases include:**\n\n"
            "- Vulnerable third parties are often critical attack vectors.\n"
            "- Personally identifiable information (PII) remains a valuable target, irrespective of financial information being stolen.\n"
            "- Outdated systems and poor patching dramatically increase risk.\n"
            "- Incident response planning and communication strategies can mitigate damage.\n"
            "- Long term recovery costs, both financial and reputational, often far exceed immediate remediation")
    

    elif intent == "Corrective":
        advice = (
            "**Strengthen future resilience through lessons learned.**\n\n"
            "- Use post-incident reports to revise controls.\n"
            "- Consider GDPR Article 32: https://www.itgovernance.co.uk/blog/gdpr-article-32-your-guide-to-the-requirements\n"
            "- Build in feedback loops for policy adaptation."
        )
    elif intent == "Directive":
        advice = (
            "**Enforce standards and obligations across sectors.**\n\n"
            "- NIS2 overview: https://www.pwc.nl/en/insights-and-publications/themes/risk-regulation/new-european-nis2-directive-stricter-requirements-for-cyber-security.html\n"
            "- Enforce ISO 27001 where applicable (Annex A – Policy Framework).\n"
            "- Embed governance through strong policy oversight."
        )
    elif intent == "Normative":
        advice = (
            "**Promote ethical norms in cyberspace.**\n\n"
            "- UN GGE norms overview: https://cyberpeaceinstitute.org/news/the-un-gge-final-report-a-milestone-in-cyber-diplomacy-but-where-is-the-accountability/\n"
            "- Avoid escalation and protect civilian infrastructure.\n"
            "- Review Floridi’s digital ethics principles."
        )
    elif intent == "Collective Defense":
        advice = (
            "**Coordinate with allies and mutual defense treaties.**\n\n"
            "- CCDCOE: https://ccdcoe.org/library/publications/ethics-and-policies-for-cyber-operation-a-nato-cooperative-cyber-defence-centre-of-excellence-initiative-new/\n"
            "- Share intelligence and response protocols.\n"
            "- See CAPSS: https://www.npsa.gov.uk/system-information-security/cyber-assurance-physical-security-systems-capss"
        )
    elif intent == "Attribution and Response":
        advice = (
            "**Attribute responsibly and plan proportional responses.**\n\n"
            "- Confirm attribution with high confidence.\n"
            "- UK National Cyber Force: https://www.gchq.gov.uk/news/ncf-responsible-cyber-power-in-practice\n"
            "- Example: https://www.gov.uk/government/news/uk-holds-china-state-affiliated-organisations-and-individuals-responsible-for-malicious-cyber-activity"
        )
    elif intent == "Strategic Ambiguity":
        advice = (
            "**Maintain unpredictability without losing control.**\n\n"
            "- Useful as a deterrent but risks misinterpretation.\n"
            "- Should not contradict humanitarian obligations.\n"
            "- NCSC Annual Review (context): https://www.ncsc.gov.uk/files/NCSC_Annual_Review_2024.pdf\n"
            "- Balance secrecy with public accountability."
        )
    elif intent == "Evaluative":
        advice = (
            "**Conduct robust policy evaluation.**\n\n"
            "- Scenario-based analysis and red teaming: https://www.geeksforgeeks.org/computer-networks/what-is-red-teaming-in-cyber-security/\n"
            "- Government cyber security policy handbook: https://www.security.gov.uk/policy-and-guidance/government-cyber-security-policy-handbook/\n"
            "- Document findings transparently for policy iteration."
        )
    else:
        advice = "No advice available for the selected intent."
    return severity, advice

# --- Sidebar (always visible, by design) ---
st.sidebar.title("Scenario Inputs and advice")
st.sidebar.subheader("Why do you need to make a policy? What happened?")

_ = st.sidebar.selectbox(
    "Select Scenario",
    ["Civilian Breach", "Military Disruption", "Corporate Attack", "Infrastructure Strike", "Data Loss"],
    key="scenario"
)
_ = st.sidebar.slider("Attack Severity (1-10)", 1, 10, 5, key="scale")
_ = st.sidebar.radio(
    "Policy Intent",
    ["Prevention", "Detection", "Mitigation", "Directive", "Corrective", "Normative",
     "Collective Defense", "Attribution and Response", "Strategic Ambiguity", "Evaluative"],
    key="intent"
)
if st.sidebar.button("Run Simulation"):
    # copy the sidebar selection into the payload used by Policy Advice
    st.session_state["simintent"] = st.session_state.get("intent", "Prevention")
    st.session_state["show_dashboard"] = True
    st.rerun()  # immediately render Policy Advice with these values


# --- Tabs for navigation ---
tab1, tab2, tab3, tab4 = st.tabs(["Risk Register","Policy Types", "Policy Advice", "Visualisations and Statistics"])

# =========================
# TAB 1 — Risk Register
# =========================
with tab1:
    df = pd.read_excel(r"C:\Users\sadie\OneDrive - UWE Bristol\Documents\Data Science\Masters Project\Risk Register - masters.xlsm")
    st.title("Risk Register")
    st.write("A risk register is a project management tool used to identify, assess and manage potential risks that could impact a projects success. "
             "There are a number of reasons why a risk register is useful; they encourage proactive planning, allign risks with strategy, they're fully customisable "
             "to whatever context necessary and they support informed decision making. ")
    st.write("Below is a risk register free to download and fill in as you wish.")
    st.markdown("https://uweacuk-my.sharepoint.com/:x:/r/personal/sadie2_wise_live_uwe_ac_uk/Documents/Documents/Data%20Science/Masters%20Project/Empty%20Risk%20Register.xlsm?d=wa033a1e78f9e4810842c72436dde604a&csf=1&web=1&e=ifOT5M")
    st.subheader("Usage and guidance")
    st.markdown("This should aid you in risk criteria and scoring")
    st.image(r"C:\Users\sadie\OneDrive - UWE Bristol\Documents\Data Science\Masters Project\useage.png")
    st.image(r"C:\Users\sadie\OneDrive - UWE Bristol\Documents\Data Science\Masters Project\definitions.png")
    st.subheader("Data from Excel File")
    st.write("There is an example illustrated below for your aid which includes generalised risks for cyber deterrance and policy making. All figures are estimated based off real world examples and sensible, educated guesses. See notes for sources")
    st.write("The example risk register is searchable allowing you to find specific examples")
    st.dataframe(df)

# =========================
# TAB 2 — Policy Types
# =========================
with tab2:
    st.header("Policy Types")
    st.markdown(
        "This page intends to give you some more detail into the types of policies you may come across..."
    )
    st.caption("Search, filter, explore details, compare policies, and send a selection to the simulation.")

    # Load & normalise columns
    df_raw = pd.read_excel(
        r"C:\Users\sadie\OneDrive - UWE Bristol\Documents\Data Science\Masters Project\Policy types.xlsx"
    ).copy()

    rename_map = {}
    for c in df_raw.columns:
        lc = c.strip().lower()
        if lc in {"policy name", "name", "policy"}:
            rename_map[c] = "Policy Name"
        elif lc in {"category", "type", "policy type"}:
            rename_map[c] = "Category"
        elif lc in {"purpose", "objective", "aim"}:
            rename_map[c] = "Purpose"
        elif lc in {"description", "desc", "details", "summary"}:
            rename_map[c] = "Description"
        elif lc in {"examples", "example", "use cases"}:
            rename_map[c] = "Examples"
        elif lc in {"link", "url", "reference"}:
            rename_map[c] = "Link"

    df_types = df_raw.rename(columns=rename_map)

    has_name = "Policy Name" in df_types.columns
    has_cat = "Category" in df_types.columns
    has_desc = "Description" in df_types.columns
    has_purpose = "Purpose" in df_types.columns
    has_examples = "Examples" in df_types.columns
    has_link = "Link" in df_types.columns

    col_a, col_b = st.columns([2, 1])
    with col_a:
        q = st.text_input("Search policies (matches any column)", "")
    with col_b:
        categories = ["All"]
        if has_cat:
            categories += sorted([c for c in df_types["Category"].dropna().astype(str).unique()])
        chosen_cat = st.selectbox("Filter by category", categories)

    df_show = df_types.copy()
    if chosen_cat != "All" and has_cat:
        df_show = df_show[df_show["Category"].astype(str) == chosen_cat]

    if q.strip():
        q_low = q.strip().lower()
        df_show = df_show[df_show.apply(
            lambda r: any(q_low in str(v).lower() for v in r.values), axis=1
        )]

    cols_to_show = [c for c in ["Policy Name", "Category", "Purpose"] if c in df_show.columns]
    st.subheader("Table of Policies")
    st.dataframe(df_show[cols_to_show] if cols_to_show else df_show, use_container_width=True)

    st.subheader("Browse Details")
    intents_catalog = {
        "prevention", "detection", "mitigation", "directive", "corrective",
        "normative", "collective defense", "attribution and response",
        "strategic ambiguity", "evaluative"
    }

    def infer_intent(source_text: str) -> Optional[str]:
        t = (source_text or "").strip().lower()
        for it in intents_catalog:
            if it in t:
                return it.title()
        return None

    max_rows = min(50, len(df_show))
    for idx, row in df_show.head(max_rows).reset_index(drop=True).iterrows():
        title = row.get("Policy Name", f"Policy #{idx+1}")
        cat = row.get("Category", "Uncategorised")
        with st.expander(f"{title} — {cat}"):
            if has_purpose:
                st.markdown(f"**Purpose:** {row['Purpose']}")
            if has_desc:
                st.markdown(f"**Description:** {row['Description']}")
            if has_examples:
                st.markdown(f"**Examples:** {row['Examples']}")
            if has_link and pd.notna(row["Link"]):
                st.markdown(f"[Open reference]({row['Link']})")

            candidate_text = " ".join(
                str(x) for x in [
                    row.get("Category", ""),
                    row.get("Purpose", ""),
                    row.get("Description", "")
                ] if pd.notna(x)
            )
            suggested_intent = infer_intent(candidate_text)

            col_int1, col_int2 = st.columns([2, 1])
            with col_int1:
                choices_sorted = sorted([i.title() for i in intents_catalog])
                idx_default = choices_sorted.index(suggested_intent) if suggested_intent in choices_sorted else 0
                chosen_intent = st.selectbox(
                    "Map to policy intent (for simulation)",
                    choices_sorted,
                    index=idx_default,
                    key=f"intent_select_{idx}"
                )
            with col_int2:
                if st.button("Use in Scenario ▶", key=f"use_in_scenario_{idx}"):
                    st.session_state["simintent"] = chosen_intent
                    st.session_state["show_dashboard"] = True
                    st.success(
                        f"Sent **{title}** → intent **{chosen_intent}** to the simulation. "
                        "Open the **Policy Advice** tab to view results."
                    )


# =========================
# TAB 3 — Policy Advice (+ Risk vs Reward)
# =========================
with tab3:
 # prefer intent pushed from Browse Details or Sidebar button; else fallback to live sidebar
    intent = st.session_state.get("simintent") or st.session_state.get("intent", "Prevention")
    scale = int(st.session_state.get("scale", 5))
    scenario = st.session_state.get("simscenario") or st.session_state.get("scenario", "Civilian Breach")

    st.title("Policy advice")

    # (optional) only show once "Run Simulation" has been pressed somewhere
    if not st.session_state.get("show_dashboard", False):
        st.info("Use **Run Simulation** in the sidebar or **Use in Scenario ▶** in Policy Types to populate this section.")
        st.stop()


    intenttips = {
        "Prevention": "Prevention - Reduce the chance of an incident (hardening, MFA, patching, email security).",
        "Detection": "Detection - Spot issues quickly (logging, alerting, endpoint telemetry).",
        "Mitigation": "Mitigation - Limit damage & recover faster (backups, IR runbooks, containment).",
        "Directive": "Directive - Set rules so everyone follows consistent controls (policies, SLAs, audits).",
        "Corrective": "Corrective - Turn lessons into permanent fixes (post-incident review, redesign, training).",
        "Normative": "Normative - Embed ethics & transparency (rights checks, public-interest test, audit trail).",
        "Collective Defense": "Collective Defense - Coordinate with partners (intel sharing, joint exercises, mutual aid).",
        "Attribution and Response": "Attribution and Response - Confirm who did it & act proportionately (legal prep, sanctions, signalling).",
        "Strategic Ambiguity": "Strategic Ambiguity  - Deter by being unpredictable, with guardrails to avoid escalation.",
        "Evaluative": "Evaluative  - Measure what works and improve (KPIs, assurance, lessons learned).",
    }

    st.markdown("### What does this intent mean?")
    st.info(intenttips.get(intent, "Configure your approach using the options below."))

    intenttoggles = {
        "Prevention": [("Enable MFA everywhere", 12), ("Patch critical systems this week", 10), ("Tighten email filtering/DMARC", 8)],
        "Detection": [("Turn on key alerts (high-severity)", 10), ("Daily review of EDR/XDR dashboard", 8), ("Create triage runbook for top 5 alerts", 8)],
        "Mitigation": [("Verify backups restore successfully", 12), ("Update incident response runbook", 9), ("Practice containment on a test host", 8)],
        "Directive": [("Approve updated security policy", 8), ("Add cyber clauses to supplier SLAs", 10), ("Schedule internal audit spot-checks", 7)],
        "Corrective": [("Run post-incident review (RCA)", 10), ("Implement hardening from findings", 9), ("Targeted retraining for affected teams", 7)],
        "Normative": [("Complete an ethics impact check", 9), ("Apply public-interest test", 7), ("Record transparent decision rationale", 6)],
        "Collective Defense": [("Share IOCs with partners/NCSC", 9), ("Join next ISAC briefing", 7), ("Agree mutual-aid contacts/MoU", 8)],
        "Attribution and Response": [("Evidence chain & attribution checklist", 9), ("Legal proportionality review", 8), ("Draft response options & comms lines", 8)],
        "Strategic Ambiguity": [("Define ambiguity guardrails", 8), ("Agree signalling channels", 7), ("Set escalation stop-loss criteria", 8)],
        "Evaluative": [("Set 3 KPIs (e.g., MTTD/MTTR + ethics)", 8), ("Plan assurance review/independent check", 8), ("Record benefits & lessons tracker", 7)],
    }

    st.markdown("### Quick Enhancements to add to your checklist")
    st.write("Add, edit and customise your own checklist. Download as a CSV file when finished to keep track!")
    toggles = intenttoggles.get(intent, [])
    cols = st.columns(3)
    checked = []
    readiness_score = 50
    for i, (label, pts) in enumerate(toggles):
        with cols[i % 3]:
            on = st.checkbox(label, key=f"intent_toggle_{intent}_{i}")
            if on:
                readiness_score += pts
                checked.append(label)

    st.markdown("### Action Checklist")
    rows = checked if checked else ["Define scope for this intent", "Assign owners", "Set next review date"]
    check_df = pd.DataFrame({
        "Action": rows,
        "Owner": [""] * len(rows),
        "Due date": [""] * len(rows),
        "Status": ["Planned"] * len(rows)
    })
    edited = st.data_editor(check_df, num_rows="dynamic", use_container_width=True)
    st.download_button("Download Checklist", edited.to_csv(index=False),
                       file_name=f"{intent.lower().replace(' ','_')}_checklist.csv", mime="text/csv")

    quicklinks = {
        "Prevention": ("NCSC: 10 Steps", "https://www.ncsc.gov.uk/collection/10-steps-to-cyber-security"),
        "Detection": ("NCSC: Logging", "https://www.ncsc.gov.uk/collection/device-security-guidance/managing-deployed-devices/logging-and-protective-monitoring"),
        "Mitigation": ("NCSC: Incident Management", "https://www.ncsc.gov.uk/collection/incident-management"),
        "Directive": ("ISO/IEC 27001 Overview", "https://www.iso.org/standard/27001"),
        "Corrective": ("NCSC: After an incident", "https://www.ncsc.gov.uk/files/Responding-to-a-cyber-incident-a-guide-for-ceos.pdf"),
        "Normative": ("UN GGE norms (overview)", "https://www.unevaluation.org/uneg_publications/uneg-norms-and-standards-evaluation-un-system"),
        "Collective Defense": ("NCSC partnerships", "https://www.ncsc.gov.uk/schemes/cyber-resilience-audit/scheme-partners"),
        "Attribution and Response": ("UK cyber strategy", "https://www.gov.uk/government/publications/national-cyber-strategy-2022"),
        "Strategic Ambiguity": ("NCSC Annual Review", "https://www.ncsc.gov.uk/files/NCSC_Annual_Review_2024.pdf"),
        "Evaluative": ("Metrics & KPIs (general)", "https://www.ncsc.gov.uk"),
    }
    if intent in quicklinks:
        label, url = quicklinks[intent]
        st.markdown("### Useful Link for your policy intent")
        st.markdown(f"[{label}]({url})")

    severity_level, policy_advice = evaluate_policy(scale, intent)
    st.subheader("Policy Impact Assessment")
    st.markdown(f"**Threat Severity Level:** `{severity_level}`")
    st.markdown(f"**Policy Intent Chosen:** `{intent}`")
    st.markdown("### Recommended Strategic Advice")
    st.info(policy_advice)

    # ----- Risk vs Reward (kept on Policy Advice tab) -----
    st.markdown("### Risk vs Reward (Ethical/Legal Risk vs Operational Benefit)")
    DEFAULT_SCORES = {
        "Prevention":              {"benefit": 8, "ethical_risk": 3},
        "Detection":               {"benefit": 7, "ethical_risk": 3},
        "Mitigation":              {"benefit": 7, "ethical_risk": 2},
        "Directive":               {"benefit": 6, "ethical_risk": 4},
        "Corrective":              {"benefit": 6, "ethical_risk": 3},
        "Normative":               {"benefit": 5, "ethical_risk": 2},
        "Collective Defense":      {"benefit": 7, "ethical_risk": 5},
        "Attribution and Response":{"benefit": 7, "ethical_risk": 6},
        "Strategic Ambiguity":     {"benefit": 6, "ethical_risk": 7},
        "Evaluative":              {"benefit": 5, "ethical_risk": 2},
    }
    base = DEFAULT_SCORES.get(intent, {"benefit": 6, "ethical_risk": 4})

    c1, c2 = st.columns(2)
    with c1:
        benefit = st.slider("Operational Benefit (0–10)", 0, 10, base["benefit"],
                            help="How much this intent helps achieve objectives?")
    with c2:
        ethical_risk = st.slider("Ethical/Legal Risk (0–10)", 0, 10, base["ethical_risk"],
                                 help="Privacy, proportionality, civilian impact, legal exposure.")

    marker_size = 10 + (int(scale) * 3)

    df_rr = pd.DataFrame([{
        "Intent": intent,
        "Operational Benefit": benefit,
        "Ethical/Legal Risk": ethical_risk,
        "Severity": int(scale)
    }])

    fig = px.scatter(
        df_rr, x="Operational Benefit", y="Ethical/Legal Risk",
        text="Intent", size=[marker_size], size_max=30,
        title="Risk vs Reward Map"
    )

    st.subheader("What does each quadrant mean?")
    st.markdown("- Top left: Moderate reward/high ethical risk")
    st.markdown("- Top right: High reward/High ethical risk")
    st.markdown("- Bottom Left: Moderare Reward/Low ethical risk")
    st.markdown("- Bottom right: High reward/Low ethical risk")

    fig.update_traces(textposition="top center")

    fig.update_layout(
        shapes=[
            dict(
                type="line", x0=5, x1=5, y0=0, y1=10, 
                line=dict(dash="dash", color = "red")
                ),
            dict(
                type="line", x0=0, x1=10, y0=5, y1=5,
                  line=dict(dash="dash", color="red")
                ),
        ],
        xaxis=dict(range=[0,10], dtick=1),
        yaxis=dict(range=[0,10], dtick=1)
    )
    st.plotly_chart(fig, use_container_width=True)

    def classify(benefit, risk):
        if benefit >= 7 and risk <= 4:
            return "High reward / Low ethical risk → Proceed with standard safeguards."
        if benefit >= 7 and risk > 4:
            return "High reward / Higher ethical risk → Proceed with strong oversight and proportionality checks."
        if benefit < 7 and risk <= 4:
            return "Moderate reward / Low ethical risk → Consider if resources allow; ensure utility."
        return "Moderate reward / Higher ethical risk → Reconsider or add safeguards (privacy, legality, civilian protection)."

    st.info(classify(benefit, ethical_risk))
    st.download_button("Download Risk vs Reward visualisation",
                       data=df_rr.to_csv(index=False).encode("utf-8"),
                       file_name="riskreward.csv",
                       mime="text/csv")

# =========================
# TAB 4 — Visualisations & Statistics
# =========================
with tab4:
    st.subheader("Below are some visualisation")

    # NCSC incidents
    ncsc = pd.DataFrame({
        "Year": [2022, 2023, 2024],
        "Incidents requiring NCSC IM support": [355, 371, 430],
        "Nationally significant incidents": [63, 62, 89]
    })
    st.subheader("NCSC incidents by year")
    fig_ncsc = px.bar(
        ncsc, x="Year",
        y=["Incidents requiring NCSC IM support", "Nationally significant incidents"],
        barmode="group",
    )
    st.plotly_chart(fig_ncsc, use_container_width=True)
    st.caption("Source: NCSC Annual Reviews")

    # Timeline
    st.subheader("Timeline of Major UK Cyber Incidents")
    timeline = pd.DataFrame([
        {"Year": 2015, "Incident": "TalkTalk data breach", "Impact": "Around 150,000 Customers' personal details accessed"},
        {"Year": 2017, "Incident": "NHS WannaCry", "Impact": "70,000 devices affected in NHS"},
        {"Year": 2018, "Incident": "British Airways Data Breach", "Impact": "400,000 customers addresses, card details and personal information stolen"},
        {"Year": 2022, "Incident": "KP snacks ransomware attack", "Impact": "Proccessing of orders and IT systems stopped"},
        {"Year": 2024, "Incident": "Leicester City Council Cyber incident", "Impact": "Sensitive information compromised"},
        {"Year": 2025, "Incident": "M&S Cyber Attacks", "Impact": "Customer data stolen, online order stopped"},
    ])

    fig_tl, ax = plt.subplots(figsize=(10, 4))
    ax.scatter(timeline["Year"], [1]*len(timeline), s=200, marker="x")
    for _, row in timeline.iterrows():
        ax.text(row["Year"], 1.05, row["Incident"], rotation=45, ha="right", va="bottom", fontsize=10)
    ax.set_title("Timeline of Major UK Cyber Incidents")
    ax.set_xlabel("Year")
    ax.set_yticks([])
    ax.set_ylim(0.9, 1.25)
    ax.grid(True, axis="x", linestyle="--", alpha=0.3)
    st.pyplot(fig_tl)

    with st.expander("Show incident notes"):
        st.dataframe(timeline, use_container_width=True)

    st.subheader("Below are some Statistics")
    st.markdown("50% of UK businesses and 32% of charities reported experiencing a cyber breach or attack in the past 12 months")
    st.markdown("This rises to 70% for medium sized businesses and 74% for large enterprises")
    st.markdown("Source: https://www.gov.uk/government/statistics/cyber-security-breaches-survey-2024/cyber-security-breaches-survey-2024")
    st.markdown("---")
    st.markdown("Phishing remains a top threat, affecting 84% of businesses and 83% of charities")
    st.markdown("Impersination attacks are seen by 35% of businesses and 37% of charities")
    st.markdown("Malware and viruses affected 17% of businesses and 14% of charities")
    st.markdown("Source: https://www.gov.uk/government/statistics/cyber-security-breaches-survey-2024/cyber-security-breaches-survey-2024")
    st.markdown("---")
    st.markdown("Over 70% of businesses use basic protections like: Updated malware protection, passwork policies, cloud backups, restricted admin rights, network firewalls")
    st.markdown("Source: https://www.gov.uk/government/statistics/cyber-security-breaches-survey-2024/cyber-security-breaches-survey-2024")
    st.markdown("---")
    st.markdown("The average cost of the most distruptive breaches are: £1205 for small businesses, £10830 for medium and large business and £460 for charities")
    st.markdown("Source: https://www.gov.uk/government/statistics/cyber-security-breaches-survey-2024/cyber-security-breaches-survey-2024")

    st.subheader("Ethical Implications")
    st.markdown(
        "These statistics highlight the need for ethical responsibility of UK organisations to: "
        "Protect user data and maintain trust; "
        "Invest in proactive security rather than reactive damage control; "
        "Educate stakeholders to reduce human error and phishing success; "
        "Report breaches transparently, especially when personal data is involved."
    )