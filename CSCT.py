import streamlit as st
import pandas as pd
import plotly.express as px
import streamlit.components.v1 as components
from pathlib import Path
from io import BytesIO
from PIL import Image
import matplotlib.pyplot as plt

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

# Tabs for navigation
tab1, tab2, tab3 , tab4 = st.tabs(["Risk Register","Policy Types", "Policy Advice", "Visualisations and Statistics"])

with tab1:
    #Risk Register Excel
    df = pd.read_excel(r"C:\Users\sadie\OneDrive - UWE Bristol\Documents\Data Science\Masters Project\Risk Register - masters.xlsm")

    st.title("Risk Register")
    st.write("A risk register is a project management tool used to identify, assess and manage potential risks that could impact a projects success. " \
    "There are a number of reasons why a risk register is useful; they encourage proactive planning, allign risks with strategy, they're fully customisable " \
    "to whatever context necessary and they support informed decision making. ")
    st.write("Below is a risk register free to download and fill in as you wish.")
    st.markdown("https://uweacuk-my.sharepoint.com/:x:/r/personal/sadie2_wise_live_uwe_ac_uk/Documents/Documents/Data%20Science/Masters%20Project/Empty%20Risk%20Register.xlsm?d=wa033a1e78f9e4810842c72436dde604a&csf=1&web=1&e=ifOT5M")
    st.subheader("Usage and guidance")
    st.markdown("This should aid you in risk criteria and scoring")
    st.image(r"C:\Users\sadie\OneDrive - UWE Bristol\Documents\Data Science\Masters Project\useage.png")
    st.image(r"C:\Users\sadie\OneDrive - UWE Bristol\Documents\Data Science\Masters Project\definitions.png")
    st.subheader("Data from Excel File")
    st.write("There is an example illustrated below for your aid which includes generalised risks for cyber deterrance and policy making. All figures are estimated based off real world examples and sensible, educated guesses." \
    "See notes for sources")
    st.write("The example risk register is searchable allowing you to find specific examples")
    st.dataframe(df)

with tab2:
    import plotly.express as px

    st.header("Policy Types")
    st.markdown("This page intends to give you some more detail into the types of policies you may come across. Cybersecurity policies provide structured approaches for responding to incidents, reducing risks, and aligning actions \
                 with ethical and legal frameworks. Each policy type reflects a different strategic intent — from prevention and detection through to mitigation, corrective measures, and broader approaches such as collective defence \
                 or normative guidance. This section introduces the key policy types, explains their purpose, and highlights how they can be applied in real-world scenarios. By understanding the strengths and limitations of each approach,\
                 decision-makers can better tailor their responses to cyber threats while balancing technical effectiveness, ethical responsibility, and organisational resilience.")
    st.caption("Search, filter, explore details, compare policies, and send a selection to the simulation.")

    # --- Load & normalise columns ---
    df_raw = pd.read_excel(
        r"C:\Users\sadie\OneDrive - UWE Bristol\Documents\Data Science\Masters Project\Policy types.xlsx"
    ).copy()

    # Standardise expected column names (case/spacing tolerant)
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

    df = df_raw.rename(columns=rename_map)

    has_name = "Policy Name" in df.columns
    has_cat = "Category" in df.columns
    has_desc = "Description" in df.columns
    has_purpose = "Purpose" in df.columns
    has_examples = "Examples" in df.columns
    has_link = "Link" in df.columns

    col_a, col_b = st.columns([2, 1])
    with col_a:
        q = st.text_input("Search policies (matches any column)", "")
    with col_b:
        categories = ["All"]
        if has_cat:
            categories += sorted([c for c in df["Category"].dropna().astype(str).unique()])
        chosen_cat = st.selectbox("Filter by category", categories)

    df_show = df.copy()
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

    def infer_intent(source_text: str) -> str | None:
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
                chosen_intent = st.selectbox(
                    "Map to policy intent (for simulation)",
                    sorted([i.title() for i in intents_catalog]),
                    index=(sorted([i.title() for i in intents_catalog]).index(suggested_intent) if suggested_intent else 0),
                    key=f"intent_select_{idx}"
                )
            with col_int2:
                if st.button("Use in Scenario ▶", key=f"use_in_scenario_{idx}"):
                    st.session_state["intent"] = chosen_intent
                    st.session_state["show_dashboard"] = True
                    st.success(
                        f"Sent **{title}** → intent **{chosen_intent}** to the simulation. "
                        "Open the **Policy Advice** tab to view results."
                    )


#side bar and tab 3

def evaluate_policy(scale: int, intent: str):
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
            "- Consider UK’s [Active Cyber Defence](https://www.ncsc.gov.uk/collection/risk-management) strategy."
        )
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
            "- Ensure continuity via backup and restoration plans."
        )
    elif intent == "Corrective":
        advice = (
            "**Strengthen future resilience through lessons learned.**\n\n"
            "- Use post-incident reports to revise controls.\n"
            "- Consider GDPR Article 32 (personal data breaches): https://www.itgovernance.co.uk/blog/gdpr-article-32-your-guide-to-the-requirements\n"
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
            "- UK National Cyber Force (responsible cyber power): https://www.gchq.gov.uk/news/ncf-responsible-cyber-power-in-practice\n"
            "- Example statement: https://www.gov.uk/government/news/uk-holds-china-state-affiliated-organisations-and-individuals-responsible-for-malicious-cyber-activity"
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

#sidebar

st.sidebar.title("Scenario Inputs and advice")
st.sidebar.subheader("Why do you need to make a policy? What happened?")

_ = st.sidebar.selectbox(
    "Select Scenario",
    ["Civilian Breach", "Military Disruption", "Corporate Attack", "Infrastructure Strike", "Data Loss"],
    key="scenario"  # sidebar-owned key
)
_ = st.sidebar.slider("Attack Severity (1-10)", 1, 10, 5, key="scale")  # sidebar-owned key
_ = st.sidebar.radio(
    "Policy Intent",
    ["Prevention", "Detection", "Mitigation", "Directive", "Corrective", "Normative",
     "Collective Defense", "Attribution and Response", "Strategic Ambiguity", "Evaluative"],
    key="intent"  # sidebar-owned key
)
if st.sidebar.button("Run Simulation"):
    st.session_state["show_dashboard"] = True

if st.session_state.get("show_dashboard"):
    # Prefer Scenario Explorer payload; fallback to sidebar values
    p = st.session_state.get("sim_payload", {})
    scale  = int(p.get("scale", st.session_state.get("scale", 5)))
    intent = p.get("intent", st.session_state.get("intent", "Prevention"))

#tab3

    # --- intent explainer ---
    st.title("Policy advice")
    intenttips = {
        "Prevention": "Reduce the chance of an incident (hardening, MFA, patching, email security).",
        "Detection": "Spot issues quickly (logging, alerting, endpoint telemetry).",
        "Mitigation": "Limit damage & recover faster (backups, IR runbooks, containment).",
        "Directive": "Set rules so everyone follows consistent controls (policies, SLAs, audits).",
        "Corrective": "Turn lessons into permanent fixes (post-incident review, redesign, training).",
        "Normative": "Embed ethics & transparency (rights checks, public-interest test, audit trail).",
        "Collective Defense": "Coordinate with partners (intel sharing, joint exercises, mutual aid).",
        "Attribution and Response": "Confirm who did it & act proportionately (legal prep, sanctions, signalling).",
        "Strategic Ambiguity": "Deter by being unpredictable, with guardrails to avoid escalation.",
        "Evaluative": "Measure what works and improve (KPIs, assurance, lessons learned).",
    }
    st.markdown("### What does this intent mean?")
    st.info(intenttips.get(intent, "Configure your approach using the options below."))

    # --- toggles -> simple checklist ---
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

    # --- quick link ---
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

    

else:
    st.markdown(" ")

    # --- Ensure intent & scale exist ---
# Prefer simulation payload if available, else fall back to sidebar inputs
if "sim_payload" in st.session_state:
    intent = st.session_state["sim_payload"]["intent"]
    scale = st.session_state["sim_payload"]["scale"]
else:
    intent = st.session_state.get("intent", "Prevention")  # fallback default
    scale = st.session_state.get("scale", 5)              # fallback default



st.markdown("### Risk vs Reward (Ethical/Legal Risk vs Operational Benefit)")

# 1) Sensible defaults per intent (0–10). Adjust freely.
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

# Get baseline for the chosen intent
base = DEFAULT_SCORES.get(intent, {"benefit": 6, "ethical_risk": 4})

# 2) Let the user nudge the scores (kept simple & transparent)
c1, c2 = st.columns(2)
with c1:
    benefit = st.slider("Operational Benefit (0–10)", 0, 10, base["benefit"], help="How much this intent helps achieve objectives?")
with c2:
    ethical_risk = st.slider("Ethical/Legal Risk (0–10)", 0, 10, base["ethical_risk"], help="Privacy, proportionality, civilian impact, legal exposure.")

# 3) Optional: reflect severity (scale) as marker size
marker_size = 10 + (int(scale) * 2 if "scale" in locals() else 10)

# 4) Build a tiny dataset for plotting
df_rr = pd.DataFrame([{
    "Intent": intent,
    "Operational Benefit": benefit,
    "Ethical/Legal Risk": ethical_risk,
    "Severity": int(scale) if "scale" in locals() else None
}])

# 5) Make a quadrant-style scatter (interactive)
fig = px.scatter(
    df_rr, x="Operational Benefit", y="Ethical/Legal Risk",
    text="Intent", size=[marker_size], size_max=30,
    title="Risk vs Reward Map"
)
fig.update_traces(textposition="top center")

# Add guideline lines for quadrants (at 5/10)
fig.update_layout(
    shapes=[
        dict(type="line", x0=5, x1=5, y0=0, y1=10, line=dict(dash="dash")),
        dict(type="line", x0=0, x1=10, y0=5, y1=5, line=dict(dash="dash")),
    ],
    xaxis=dict(range=[0,10], dtick=1),
    yaxis=dict(range=[0,10], dtick=1)
)
st.plotly_chart(fig, use_container_width=True)

# 6) Simple narrative to make it assessor-friendly
def classify(benefit, risk):
    if benefit >= 7 and risk <= 4:
        return "High reward / Low ethical risk → **Proceed** with standard safeguards."
    if benefit >= 7 and risk > 4:
        return "High reward / Higher ethical risk → **Proceed with strong oversight** and proportionality checks."
    if benefit < 7 and risk <= 4:
        return "Moderate reward / Low ethical risk → **Consider** if resources allow; ensure utility."
    return "Moderate reward / Higher ethical risk → **Reconsider or add safeguards** (privacy, legality, civilian protection)."

st.info(classify(benefit, ethical_risk))

# download
csv_bytes = df_rr.to_csv(index=False).encode("utf-8")
st.download_button("Download Risk vs Reward graph", data=csv_bytes, file_name="risk_vs_reward_snapshot.csv", mime="text/csv")



with tab4:
    st.subheader("Below are some visualisation")

#NCSC incidents (from Annual Review 2023/2024)
    ncsc = pd.DataFrame({
        "Year": [2023, 2024],
        "Incidents requiring NCSC IM support": [371, 430],
        "Nationally significant incidents": [62, 89]
    })
    st.subheader("NCSC incidents by year")
    fig_ncsc = px.bar(
        ncsc, x="Year",
        y=["Incidents requiring NCSC IM support", "Nationally significant incidents"],
        barmode="group",
    )

    st.plotly_chart(fig_ncsc, use_container_width=True)
    st.caption("Source: NCSC Annual Reviews 2023 & 2024. See notes in report for methodology.")

#timeline
st.subheader("Timeline of Major UK Cyber Incidents")

timeline = pd.DataFrame([
    {"Year": 2015, "Incident": "TalkTalk data breach", "Impact": "Around 150,000 Customers' personal details accessed"},
    {"Year": 2017, "Incident": "NHS WannaCry", "Impact": "70,000 devices affected in NHS"},
    {"Year": 2018, "Incident": "British Airways Data Breach", "Impact": "400,000 customers addresses, card details and personal information stolen"},
    {"Year": 2022, "Incident": "KP snacks ransomware attack", "Impact": "Proccessing of orders and IT systems stopped"},
    {"Year": 2024, "Incident": "Leicester City Council Cyber incident", "Impact": "Sensitive information compromised"},
    {"Year": 2025, "Incident": "M&S Cyber Attacks", "Impact": "Customer data stolen, online order stopped"},
])

fig, ax = plt.subplots(figsize=(10, 4))
ax.scatter(timeline["Year"], [1]*len(timeline), s=200, marker="x")
for _, row in timeline.iterrows():
    ax.text(row["Year"], 1.05, row["Incident"], rotation=45, ha="right", va="bottom", fontsize=10)

ax.set_title("Timeline of Major UK Cyber Incidents")
ax.set_xlabel("Year")
ax.set_yticks([])
ax.set_ylim(0.9, 1.25)
ax.grid(True, axis="x", linestyle="--", alpha=0.3)

st.pyplot(fig)

with st.expander("Show incident notes"):
    st.dataframe(timeline, use_container_width=True)

st.subheader("Below are some Statistics")

st.markdown("50% of UK businesses and 32% of charities reported experiencing a cyber breach or attack in the past 12 months")
st.markdown("This rises to 70% for medium sized businesses and 74% for large enterprises")
st.markdown("Source: https://www.gov.uk/government/statistics/cyber-security-breaches-survey-2024/cyber-security-breaches-survey-2024")
st.markdown("--------------------------------------------------------------------")
st.markdown("Phishing remains a top threat, affecting 84% of businesses and 83% of charities")
st.markdown("Impersination attacks are seen by 35% of businesses and 37% of charities")
st.markdown("Malware and viruses affected 17% of businesses and 14% of charities")
st.markdown("Source: https://www.gov.uk/government/statistics/cyber-security-breaches-survey-2024/cyber-security-breaches-survey-2024")
st.markdown("--------------------------------------------------------------------")
st.markdown("Over 70% of businesses use basic protections like: Updated malware protection, passwork policies, cloud backups, restricted admin rights, network firewalls")
st.markdown("Source: https://www.gov.uk/government/statistics/cyber-security-breaches-survey-2024/cyber-security-breaches-survey-2024")
st.markdown("--------------------------------------------------------------------")
st.markdown("The average cost of the most distruptive breaches are: £1205 for small businesses, £10830 for medium and large business and £460 for charities")
st.markdown("Source: https://www.gov.uk/government/statistics/cyber-security-breaches-survey-2024/cyber-security-breaches-survey-2024")

st.subheader("Ethical Implications")
st.markdown("These statistics highlight the need for ethical responsibility of UK organisations to: " \
"Protect user data and maintain trust" \
"Invest in proactive security rather than reactive damage control." \
" Educate stakeholders to reduce human error and phishing success." \
" Report breaches transparently, especially when personal data is involved.")

