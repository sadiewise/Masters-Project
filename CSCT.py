import streamlit as st
import pandas as pd
import plotly.express as px
import streamlit.components.v1 as components
from pathlib import Path

st.title("Ethical Cybersecurity Dashboard to Aid Policy Making and Cyber Deterrence Strategies In the UK")
st.markdown("Dashboard showing ethical and operational impacts of proposed cyber policies.")
st.markdown("21019207 - MSc Data Science - CSCT Masters Project")

st.set_page_config(page_title="Cyber Policy Dashboard", layout="wide")

# Tabs for navigation
tab1, tab2, tab3 , tab4 = st.tabs(["Risk Register","Policy Types", "Policy Advice", "Visualisations"])

with tab1:
    #Risk Register Excel
    df = pd.read_excel(r"C:\Users\sadie\OneDrive - UWE Bristol\Documents\Data Science\Masters Project\Risk Register - masters.xlsm")

    st.title("Risk Register")
    st.write("A risk register is a project management tool used to identify, assess and manage potential risks that could impact a projects success. " \
    "There are a number of reasons why a risk register is useful; they encourage proactive planning, allign risks with strategy, they're fully customisable " \
    "to whatever context necessary and they support informed decision making. ")
    st.write("Below is a risk register free to download and fill in as you wish.")
    st.markdown("https://uweacuk-my.sharepoint.com/:x:/r/personal/sadie2_wise_live_uwe_ac_uk/Documents/Documents/Data%20Science/Masters%20Project/Empty%20Risk%20Register.xlsm?d=wa033a1e78f9e4810842c72436dde604a&csf=1&web=1&e=ifOT5M")
    st.subheader("Data from Excel File")
    st.write("There is an example illustrated below for your aid which includes generalised risks for cyber deterrance and policy making. All figures are estimated based off real world examples and sensible, educated guesses." \
    "See notes for sources")
    st.write("The example risk register is searchable allowing you to find specific examples")
    st.dataframe(df)

with tab2:
    import plotly.express as px

    st.header("Policy Types")
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

    #if not has_name:
        #st.warning("Column 'Policy Name' wasn’t found (tried to infer). Showing raw table below.")
        #st.dataframe(df_raw, use_container_width=True)

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


#side bar
import streamlit as st
import pandas as pd


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


st.sidebar.title("Scenario Inputs and advice")
st.sidebar.subheader("Why do you need to make a policy? What happened?")

scenario = st.sidebar.selectbox(
    "Select Scenario",
    ["Civilian Breach", "Military Disruption", "Corporate Attack", "Infrastructure Strike", "Data Loss"],
    key="scenario"
)
attack_scale = st.sidebar.slider("Attack Severity (1-10)", 1, 10, 5, key="scale")
intent = st.sidebar.radio(
    "Policy Intent",
    ["Prevention", "Detection", "Mitigation", "Directive", "Corrective", "Normative",
     "Collective Defense", "Attribution and Response", "Strategic Ambiguity", "Evaluative"],
    key="intent"
)

if st.sidebar.button("Run Simulation"):
    st.session_state["show_dashboard"] = True


if st.session_state.get("show_dashboard"):
    st.title("Policy advice")


    scale = int(st.session_state.get("scale", attack_scale))
    intent = st.session_state.get("intent", intent)


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

   
    intenttoggles = {
        "Prevention": [
            ("Enable MFA everywhere", 12),
            ("Patch critical systems this week", 10),
            ("Tighten email filtering/DMARC", 8),
        ],
        "Detection": [
            ("Turn on key alerts (high-severity)", 10),
            ("Daily review of EDR/XDR dashboard", 8),
            ("Create triage runbook for top 5 alerts", 8),
        ],
        "Mitigation": [
            ("Verify backups restore successfully", 12),
            ("Update incident response runbook", 9),
            ("Practice containment on a test host", 8),
        ],
        "Directive": [
            ("Approve updated security policy", 8),
            ("Add cyber clauses to supplier SLAs", 10),
            ("Schedule internal audit spot-checks", 7),
        ],
        "Corrective": [
            ("Run post-incident review (RCA)", 10),
            ("Implement hardening from findings", 9),
            ("Targeted retraining for affected teams", 7),
        ],
        "Normative": [
            ("Complete an ethics impact check", 9),
            ("Apply public-interest test", 7),
            ("Record transparent decision rationale", 6),
        ],
        "Collective Defense": [
            ("Share IOCs with partners/NCSC", 9),
            ("Join next ISAC briefing", 7),
            ("Agree mutual-aid contacts/MoU", 8),
        ],
        "Attribution and Response": [
            ("Evidence chain & attribution checklist", 9),
            ("Legal proportionality review", 8),
            ("Draft response options & comms lines", 8),
        ],
        "Strategic Ambiguity": [
            ("Define ambiguity guardrails", 8),
            ("Agree signalling channels", 7),
            ("Set escalation stop-loss criteria", 8),
        ],
        "Evaluative": [
            ("Set 3 KPIs (e.g., MTTD/MTTR + ethics)", 8),
            ("Plan assurance review/independent check", 8),
            ("Record benefits & lessons tracker", 7),
        ],
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

else:
    st.info("Choose options in the sidebar and press **Run Simulation** to see advice here.")


with tab4:
    st.markdown("Below are some visualisation")

with tab4:
    import pandas as pd
    import plotly.express as px
    import streamlit as st

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
        title="Incidents triaged by NCSC IM team & nationally significant subset"
    )
    st.plotly_chart(fig_ncsc, use_container_width=True)
    st.caption("Source: NCSC Annual Reviews 2023 & 2024. See notes in report for methodology.")

    # 2) UK breach prevalence (DSIT Cyber Security Breaches Survey 2024 → 2025)
    breaches = pd.DataFrame({
        "Year": [2024, 2025],
        "Businesses reporting breaches (%)": [50, 43],
        "Charities reporting breaches (%)": [32, 30],
    })
    st.subheader("UK organisations reporting a breach (12-month prevalence)")
    fig_breach = px.bar(
        breaches, x="Year",
        y=["Businesses reporting breaches (%)", "Charities reporting breaches (%)"],
        barmode="group",
        title="Breach prevalence among businesses & charities"
    )
    st.plotly_chart(fig_breach, use_container_width=True)
    st.caption("Source: UK Cyber Security Breaches Survey 2025 (with 2024 comparator).")

    #Forward look: AI & the threat (context panel)
    st.subheader("Forward look: AI and the cyber threat (to 2027)")
    st.info(
        "NCSC assesses that AI will increase the frequency and sophistication of cyber attacks through 2027 "
        "by lowering entry barriers (phishing/social engineering) and enhancing capability (discovery, tooling, scale)."
    )
    st.caption("Source: NCSC assessments on the near-term impact of AI on the cyber threat.")


   

