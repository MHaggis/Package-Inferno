import streamlit as st
import psycopg2
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import os
import yaml
from pathlib import Path

st.set_page_config(page_title="PackageInferno Dashboard", page_icon="🔥", layout="wide")

DB_URL = os.environ.get('DB_URL', 'postgres://piuser:pipass@localhost:5432/packageinferno')

@st.cache_resource
def get_db_conn():
    return psycopg2.connect(DB_URL)

def run_query(query, params=None):
    conn = get_db_conn()
    df = pd.read_sql_query(query, conn, params=params)
    return df

st.title("🔥 PackageInferno Dashboard")
st.markdown("**npm supply-chain threat scanner** — analyze packages for malicious patterns, lifecycle hooks, and obfuscation")

tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(["📊 Overview", "🔍 Search Packages", "⚠️ High Risk", "🎯 C2 Analysis", "📈 Analytics", "⚙️ Settings"])

with tab1:
    st.header("Summary Stats")
    
    summary_query = """
    SELECT 
        COUNT(DISTINCT p.id) as total_packages,
        COUNT(DISTINCT v.id) as total_versions,
        COUNT(f.id) as total_findings,
        COUNT(DISTINCT CASE WHEN s.label = 'malicious' THEN p.id END) as malicious_packages,
        COUNT(DISTINCT CASE WHEN s.label = 'suspicious' THEN p.id END) as suspicious_packages
    FROM packages p
    LEFT JOIN versions v ON p.id = v.package_id
    LEFT JOIN findings f ON v.id = f.version_id
    LEFT JOIN scores s ON v.id = s.version_id;
    """
    summary = run_query(summary_query)
    
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total Packages", f"{summary['total_packages'][0]:,}")
    col2.metric("Total Findings", f"{summary['total_findings'][0]:,}")
    col3.metric("Malicious", summary['malicious_packages'][0])
    col4.metric("Suspicious", summary['suspicious_packages'][0])
    col5.metric("Versions", f"{summary['total_versions'][0]:,}")
    
    st.markdown("---")
    
    col_a, col_b = st.columns(2)
    
    with col_a:
        st.subheader("Findings by Rule Type")
        rule_query = """
        SELECT f.rule, COUNT(*) as count
        FROM findings f
        GROUP BY f.rule
        ORDER BY count DESC;
        """
        rule_data = run_query(rule_query)
        fig_pie = px.pie(rule_data, values='count', names='rule', title='Distribution of Finding Types')
        st.plotly_chart(fig_pie, use_container_width=True)
    
    with col_b:
        st.subheader("Severity Breakdown")
        sev_query = """
        SELECT f.severity, COUNT(*) as count
        FROM findings f
        GROUP BY f.severity
        ORDER BY 
            CASE f.severity 
                WHEN 'high' THEN 1 
                WHEN 'medium' THEN 2 
                WHEN 'low' THEN 3 
            END;
        """
        sev_data = run_query(sev_query)
        fig_bar = px.bar(sev_data, x='severity', y='count', title='Findings by Severity',
                         color='severity', color_discrete_map={'high':'red','medium':'orange','low':'yellow'})
        st.plotly_chart(fig_bar, use_container_width=True)
    
    st.subheader("Top 20 Riskiest Packages")
    top_query = """
    SELECT 
        p.name,
        v.version,
        COUNT(f.id) as finding_count,
        string_agg(DISTINCT f.rule, ', ') as triggered_rules
    FROM findings f
    JOIN versions v ON f.version_id = v.id
    JOIN packages p ON v.package_id = p.id
    GROUP BY p.name, v.version
    ORDER BY finding_count DESC
    LIMIT 20;
    """
    top_packages = run_query(top_query)
    st.dataframe(top_packages, use_container_width=True, height=400)

with tab2:
    st.header("Search Packages")
    
    col_search, col_filter = st.columns([3, 1])
    with col_search:
        search_term = st.text_input("Enter package name (partial match)", placeholder="e.g., lodash, react")
    with col_filter:
        label_filter = st.selectbox("Filter by risk", ["All", "Malicious", "Suspicious", "Clean"])
    
    if search_term or label_filter != "All":
        # Build WHERE clause based on filters
        where_clauses = []
        params = []
        
        if search_term:
            where_clauses.append("p.name ILIKE %s")
            params.append(f'%{search_term}%')
        
        if label_filter != "All":
            where_clauses.append("s.label = %s")
            params.append(label_filter.lower())
        
        where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
        
        search_query = f"""
        SELECT 
            p.name,
            v.version,
            COUNT(f.id) as findings,
            string_agg(DISTINCT f.rule, ', ') as rules,
            MAX(s.score) as score,
            MAX(s.label) as label
        FROM packages p
        JOIN versions v ON p.id = v.package_id
        LEFT JOIN findings f ON v.id = f.version_id
        LEFT JOIN scores s ON v.id = s.version_id
        WHERE {where_sql}
        GROUP BY p.name, v.version
        ORDER BY COALESCE(MAX(s.score), 0) DESC, findings DESC NULLS LAST
        LIMIT 500;
        """
        results = run_query(search_query, tuple(params) if params else None)
        
        if len(results) > 0:
            filter_desc = f" with risk={label_filter}" if label_filter != "All" else ""
            search_desc = f" matching '{search_term}'" if search_term else ""
            st.write(f"Found **{len(results)}** packages{search_desc}{filter_desc}")
            st.dataframe(results, use_container_width=True)
            
            selected_pkg = st.selectbox("Select package to view details", results['name'].unique())
            
            if selected_pkg:
                st.subheader(f"Findings for {selected_pkg}")
                findings_query = """
                SELECT 
                    f.rule,
                    f.severity,
                    f.details,
                    f.file_path
                FROM findings f
                JOIN versions v ON f.version_id = v.id
                JOIN packages p ON v.package_id = p.id
                WHERE p.name = %s
                ORDER BY 
                    CASE f.severity 
                        WHEN 'high' THEN 1 
                        WHEN 'medium' THEN 2 
                        WHEN 'low' THEN 3 
                    END;
                """
                findings_df = run_query(findings_query, (selected_pkg,))
                
                for idx, row in findings_df.iterrows():
                    with st.expander(f"{row['rule']} - {row['severity']}", expanded=(idx<3)):
                        details = row['details']
                        if isinstance(details, str):
                            details = json.loads(details)
                        
                        # Show explanation prominently if present
                        if details and 'explanation' in details:
                            st.warning(f"**Why this matters:** {details['explanation']}")
                        
                        st.json(details if details else {})
                        if row['file_path']:
                            st.code(row['file_path'], language='text')
        else:
            st.info("No packages found")

with tab3:
    st.header("High Risk Packages")
    
    st.subheader("Lifecycle Scripts (Install Hooks)")
    lifecycle_query = """
    SELECT DISTINCT
        p.name,
        v.version,
        f.details->>'key' as script_type,
        f.details->>'value' as command
    FROM findings f
    JOIN versions v ON f.version_id = v.id
    JOIN packages p ON v.package_id = p.id
    WHERE f.rule = 'lifecycle_script'
    ORDER BY p.name
    LIMIT 100;
    """
    lifecycle_df = run_query(lifecycle_query)
    st.dataframe(lifecycle_df, use_container_width=True, height=300)
    
    st.markdown("---")
    
    st.subheader("Big Base64 Blobs (Obfuscation)")
    base64_query = """
    SELECT 
        p.name,
        v.version,
        f.details->>'path' as file_path,
        (f.details->>'size')::int as size_bytes
    FROM findings f
    JOIN versions v ON f.version_id = v.id
    JOIN packages p ON v.package_id = p.id
    WHERE f.rule = 'big_base64_blob'
    ORDER BY size_bytes DESC
    LIMIT 50;
    """
    base64_df = run_query(base64_query)
    if len(base64_df) > 0:
        base64_df['size_mb'] = (base64_df['size_bytes'] / 1024 / 1024).round(2)
        st.dataframe(base64_df[['name', 'version', 'file_path', 'size_mb']], use_container_width=True, height=300)
    else:
        st.info("No base64 obfuscation findings yet")
    
    st.markdown("---")
    
    st.subheader("child_process Usage")
    child_process_query = """
    SELECT DISTINCT
        p.name,
        f.details->>'path' as file_path
    FROM findings f
    JOIN versions v ON f.version_id = v.id
    JOIN packages p ON v.package_id = p.id
    WHERE f.details->>'pattern' LIKE '%child_process%'
    LIMIT 50;
    """
    cp_df = run_query(child_process_query)
    st.dataframe(cp_df, use_container_width=True, height=300)
    
    st.markdown("---")
    
    st.subheader("🎣 Phishing Infrastructure")
    st.caption("HTML files with credential forms, fake CAPTCHAs, and CDN loading")
    
    phishing_query = """
    SELECT DISTINCT
        p.name,
        v.version,
        f.rule,
        f.severity,
        f.details::jsonb->>'form_actions' as form_targets,
        f.details::jsonb->>'cdn_urls' as cdn_urls,
        f.details::jsonb->>'iframe_urls' as iframe_urls,
        f.details::jsonb->>'button_samples' as button_samples,
        f.details::jsonb->>'explanation' as explanation
    FROM findings f
    JOIN versions v ON f.version_id = v.id
    JOIN packages p ON v.package_id = p.id
    WHERE f.rule IN ('phishing_form', 'external_cdn_load', 'fake_captcha', 'iframe_embed')
    ORDER BY f.severity DESC, p.name
    LIMIT 100;
    """
    phishing_df = run_query(phishing_query)
    
    if len(phishing_df) > 0:
        st.dataframe(phishing_df, use_container_width=True, height=400)
        st.info(f"Found {len(phishing_df)} phishing-related findings across packages")
    else:
        st.info("No phishing infrastructure detected yet. Scan packages with HTML/PHP files to populate this section.")
    
    st.markdown("---")
    
    st.subheader("🐍 Suspicious Scripts")
    st.caption("Python/shell scripts with web servers, port binding, or downloads")
    
    scripts_query = """
    SELECT DISTINCT
        p.name,
        v.version,
        f.rule,
        f.severity,
        f.details::jsonb->>'frameworks' as frameworks,
        f.details::jsonb->>'methods' as methods,
        f.details::jsonb->>'explanation' as explanation
    FROM findings f
    JOIN versions v ON f.version_id = v.id
    JOIN packages p ON v.package_id = p.id
    WHERE f.rule IN ('http_server', 'port_binding', 'script_download')
    ORDER BY f.severity DESC, p.name
    LIMIT 100;
    """
    scripts_df = run_query(scripts_query)
    
    if len(scripts_df) > 0:
        st.dataframe(scripts_df, use_container_width=True, height=400)
        st.info(f"Found {len(scripts_df)} suspicious script findings")
    else:
        st.info("No suspicious scripts detected yet.")

with tab4:
    st.header("🎯 C2 Webhook Analysis")
    st.markdown("**Command & Control (C2) infrastructure detection** — packages making connections to Discord, Slack, Telegram, and other exfiltration channels")
    
    # Overall C2 stats
    c2_stats_query = """
    SELECT 
        COUNT(DISTINCT p.id) as packages_with_c2,
        COUNT(*) as total_c2_detections,
        COUNT(DISTINCT CASE WHEN s.label = 'malicious' THEN p.id END) as malicious_with_c2,
        COUNT(DISTINCT CASE WHEN s.label = 'suspicious' THEN p.id END) as suspicious_with_c2
    FROM findings f
    JOIN versions v ON f.version_id = v.id
    JOIN packages p ON v.package_id = p.id
    LEFT JOIN scores s ON v.id = s.version_id
    WHERE f.rule = 'c2_webhook';
    """
    c2_stats = run_query(c2_stats_query)
    
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Packages with C2", c2_stats['packages_with_c2'][0])
    col2.metric("Total Detections", c2_stats['total_c2_detections'][0])
    col3.metric("Malicious", c2_stats['malicious_with_c2'][0])
    col4.metric("Suspicious", c2_stats['suspicious_with_c2'][0])
    
    st.markdown("---")
    
    # Top suspicious packages with C2
    st.subheader("🔴 Most Suspicious Packages with C2 Webhooks")
    top_c2_query = """
    SELECT 
        p.name,
        v.version,
        s.score,
        s.label,
        COUNT(*) FILTER (WHERE f.rule = 'c2_webhook') as c2_count,
        COUNT(*) FILTER (WHERE f.rule = 'env_snoop') as env_snoop_count,
        COUNT(*) FILTER (WHERE f.rule = 'writes_outside_pkg') as writes_count,
        COUNT(*) as total_findings
    FROM findings f
    JOIN versions v ON f.version_id = v.id
    JOIN packages p ON v.package_id = p.id
    LEFT JOIN scores s ON v.id = s.version_id
    WHERE p.id IN (
        SELECT DISTINCT p2.id 
        FROM findings f2
        JOIN versions v2 ON f2.version_id = v2.id
        JOIN packages p2 ON v2.package_id = p2.id
        WHERE f2.rule = 'c2_webhook'
    )
    GROUP BY p.name, v.version, s.score, s.label
    ORDER BY s.score DESC NULLS LAST, total_findings DESC
    LIMIT 50;
    """
    top_c2_df = run_query(top_c2_query)
    
    if len(top_c2_df) > 0:
        # Color code by label
        def highlight_risk(row):
            if row['label'] == 'malicious':
                return ['background-color: #ff4444; color: white'] * len(row)
            elif row['label'] == 'suspicious':
                return ['background-color: #ffaa00; color: black'] * len(row)
            return [''] * len(row)
        
        st.dataframe(
            top_c2_df.style.apply(highlight_risk, axis=1),
            use_container_width=True,
            height=400
        )
        
        # Stats breakdown
        col_a, col_b = st.columns(2)
        
        with col_a:
            st.subheader("C2 Detection Distribution")
            
            # Count packages by C2 detection count
            c2_dist_query = """
            WITH c2_counts AS (
                SELECT 
                    p.id,
                    p.name,
                    COUNT(*) as c2_count
                FROM findings f
                JOIN versions v ON f.version_id = v.id
                JOIN packages p ON v.package_id = p.id
                WHERE f.rule = 'c2_webhook'
                GROUP BY p.id, p.name
            ),
            ranges AS (
                SELECT 
                    CASE 
                        WHEN c2_count = 1 THEN '1'
                        WHEN c2_count BETWEEN 2 AND 5 THEN '2-5'
                        WHEN c2_count BETWEEN 6 AND 10 THEN '6-10'
                        WHEN c2_count BETWEEN 11 AND 20 THEN '11-20'
                        ELSE '20+'
                    END as c2_range
                FROM c2_counts
            )
            SELECT 
                c2_range,
                COUNT(*) as package_count
            FROM ranges
            GROUP BY c2_range
            ORDER BY 
                CASE c2_range
                    WHEN '1' THEN 1
                    WHEN '2-5' THEN 2
                    WHEN '6-10' THEN 3
                    WHEN '11-20' THEN 4
                    ELSE 5
                END;
            """
            c2_dist_df = run_query(c2_dist_query)
            if len(c2_dist_df) > 0:
                fig_c2_dist = px.bar(c2_dist_df, x='c2_range', y='package_count', 
                                     title='Packages by C2 Detection Count',
                                     labels={'c2_range': 'C2 Detections', 'package_count': 'Package Count'})
                st.plotly_chart(fig_c2_dist, use_container_width=True)
        
        with col_b:
            st.subheader("C2 Risk Correlation")
            st.caption("Packages with C2 + other high-risk indicators")
            
            # Correlation analysis
            corr_query = """
            SELECT 
                COUNT(DISTINCT CASE WHEN has_c2 AND has_env THEN id END) as c2_plus_env,
                COUNT(DISTINCT CASE WHEN has_c2 AND has_write THEN id END) as c2_plus_write,
                COUNT(DISTINCT CASE WHEN has_c2 AND has_lifecycle THEN id END) as c2_plus_lifecycle,
                COUNT(DISTINCT CASE WHEN has_c2 AND has_obfusc THEN id END) as c2_plus_obfuscation
            FROM (
                SELECT 
                    p.id,
                    MAX(CASE WHEN f.rule = 'c2_webhook' THEN 1 ELSE 0 END) > 0 as has_c2,
                    MAX(CASE WHEN f.rule = 'env_snoop' THEN 1 ELSE 0 END) > 0 as has_env,
                    MAX(CASE WHEN f.rule = 'writes_outside_pkg' THEN 1 ELSE 0 END) > 0 as has_write,
                    MAX(CASE WHEN f.rule = 'lifecycle_script' AND f.severity = 'high' THEN 1 ELSE 0 END) > 0 as has_lifecycle,
                    MAX(CASE WHEN f.rule IN ('big_base64_blob', 'high_entropy_blob') THEN 1 ELSE 0 END) > 0 as has_obfusc
                FROM findings f
                JOIN versions v ON f.version_id = v.id
                JOIN packages p ON v.package_id = p.id
                GROUP BY p.id
            ) sub
            WHERE has_c2;
            """
            corr_df = run_query(corr_query)
            
            if len(corr_df) > 0:
                corr_data = pd.DataFrame({
                    'Indicator': ['+ Env Snoop', '+ FS Writes', '+ Lifecycle', '+ Obfuscation'],
                    'Count': [
                        corr_df['c2_plus_env'][0],
                        corr_df['c2_plus_write'][0],
                        corr_df['c2_plus_lifecycle'][0],
                        corr_df['c2_plus_obfuscation'][0]
                    ]
                })
                fig_corr = px.bar(corr_data, x='Indicator', y='Count', 
                                  title='C2 + Other Risk Factors',
                                  color='Count', color_continuous_scale='Reds')
                st.plotly_chart(fig_corr, use_container_width=True)
        
        st.markdown("---")
        
        # Domain inference
        st.subheader("C2 Infrastructure Types (Inferred)")
        st.caption("Detected from file paths and content patterns")
        
        domain_query = """
        WITH c2_files AS (
            SELECT 
                p.name,
                v.version,
                f.file_path,
                f.details::jsonb->>'path' as detail_path
            FROM findings f
            JOIN versions v ON f.version_id = v.id
            JOIN packages p ON v.package_id = p.id
            WHERE f.rule = 'c2_webhook'
        ),
        domain_detection AS (
            SELECT 
                name,
                version,
                COALESCE(file_path, detail_path) as path,
                CASE 
                    WHEN COALESCE(file_path, detail_path) ~* 'discord' THEN 'Discord (discord.com/api)'
                    WHEN COALESCE(file_path, detail_path) ~* 'slack' THEN 'Slack (hooks.slack.com)'
                    WHEN COALESCE(file_path, detail_path) ~* 'telegram' THEN 'Telegram (api.telegram.org)'
                    WHEN COALESCE(file_path, detail_path) ~* 'pastebin' THEN 'Pastebin (pastebin.com)'
                    WHEN COALESCE(file_path, detail_path) ~* 'ngrok' THEN 'Ngrok (ngrok.io)'
                    WHEN COALESCE(file_path, detail_path) ~* 'webhook' THEN 'Generic Webhook'
                    ELSE 'Other/Unknown'
                END as detected_domain
            FROM c2_files
        )
        SELECT 
            detected_domain,
            COUNT(*) as total_findings,
            COUNT(DISTINCT name) as unique_packages
        FROM domain_detection
        GROUP BY detected_domain
        ORDER BY total_findings DESC;
        """
        domain_df = run_query(domain_query)
        
        if len(domain_df) > 0:
            col_chart, col_table = st.columns([2, 1])
            
            with col_chart:
                fig_domain = px.pie(domain_df, values='total_findings', names='detected_domain',
                                   title='C2 Infrastructure Types',
                                   hole=0.3)
                st.plotly_chart(fig_domain, use_container_width=True)
            
            with col_table:
                st.dataframe(domain_df, use_container_width=True, hide_index=True)
        
        # Sample packages per domain type
        st.markdown("---")
        st.subheader("📦 Sample Packages by C2 Type")
        
        samples_query = """
        WITH c2_files AS (
            SELECT 
                p.name,
                v.version,
                s.score,
                s.label,
                f.file_path,
                f.details::jsonb->>'path' as detail_path
            FROM findings f
            JOIN versions v ON f.version_id = v.id
            JOIN packages p ON v.package_id = p.id
            LEFT JOIN scores s ON v.id = s.version_id
            WHERE f.rule = 'c2_webhook'
        )
        SELECT 
            name,
            version,
            score,
            label,
            CASE 
                WHEN COALESCE(file_path, detail_path) ~* 'discord' THEN 'Discord'
                WHEN COALESCE(file_path, detail_path) ~* 'slack' THEN 'Slack'
                WHEN COALESCE(file_path, detail_path) ~* 'telegram' THEN 'Telegram'
                WHEN COALESCE(file_path, detail_path) ~* 'pastebin' THEN 'Pastebin'
                WHEN COALESCE(file_path, detail_path) ~* 'ngrok' THEN 'Ngrok'
                WHEN COALESCE(file_path, detail_path) ~* 'webhook' THEN 'Generic Webhook'
                ELSE 'Other'
            END as c2_type,
            COALESCE(file_path, detail_path) as detection_path
        FROM c2_files
        ORDER BY score DESC NULLS LAST
        LIMIT 100;
        """
        samples_df = run_query(samples_query)
        
        if len(samples_df) > 0:
            selected_c2_type = st.selectbox(
                "Filter by C2 type",
                ['All'] + sorted(samples_df['c2_type'].unique().tolist())
            )
            
            if selected_c2_type != 'All':
                filtered_samples = samples_df[samples_df['c2_type'] == selected_c2_type]
            else:
                filtered_samples = samples_df
            
            st.dataframe(filtered_samples, use_container_width=True, height=400)
    else:
        st.info("No C2 webhook detections found yet. Keep analyzing packages!")

with tab5:
    st.header("Analytics")
    
    st.subheader("Finding Trends Over Time")
    time_query = """
    SELECT 
        DATE(v.analyzed_at) as date,
        COUNT(f.id) as findings,
        COUNT(DISTINCT p.id) as packages
    FROM findings f
    JOIN versions v ON f.version_id = v.id
    JOIN packages p ON v.package_id = p.id
    WHERE v.analyzed_at IS NOT NULL
    GROUP BY DATE(v.analyzed_at)
    ORDER BY date DESC
    LIMIT 30;
    """
    time_df = run_query(time_query)
    if len(time_df) > 0:
        fig_time = go.Figure()
        fig_time.add_trace(go.Scatter(x=time_df['date'], y=time_df['findings'], name='Findings', mode='lines+markers'))
        fig_time.add_trace(go.Scatter(x=time_df['date'], y=time_df['packages'], name='Packages', mode='lines+markers', yaxis='y2'))
        fig_time.update_layout(
            title='Analysis Activity Over Time',
            yaxis=dict(title='Findings'),
            yaxis2=dict(title='Packages Analyzed', overlaying='y', side='right')
        )
        st.plotly_chart(fig_time, use_container_width=True)
    
    st.markdown("---")
    
    col_x, col_y = st.columns(2)
    
    with col_x:
        st.subheader("Top Rules by Package Count")
        rule_pkg_query = """
        SELECT 
            f.rule,
            COUNT(DISTINCT v.package_id) as packages_affected
        FROM findings f
        JOIN versions v ON f.version_id = v.id
        GROUP BY f.rule
        ORDER BY packages_affected DESC;
        """
        rule_pkg_df = run_query(rule_pkg_query)
        fig_rule = px.bar(rule_pkg_df, x='rule', y='packages_affected', title='Packages Affected by Rule')
        st.plotly_chart(fig_rule, use_container_width=True)
    
    with col_y:
        st.subheader("Distribution by Finding Count")
        dist_query = """
        WITH ranges AS (
            SELECT 
                CASE 
                    WHEN cnt = 0 THEN '0'
                    WHEN cnt BETWEEN 1 AND 5 THEN '1-5'
                    WHEN cnt BETWEEN 6 AND 10 THEN '6-10'
                    WHEN cnt BETWEEN 11 AND 50 THEN '11-50'
                    ELSE '50+'
                END as finding_range
            FROM (
                SELECT p.id, COUNT(f.id) as cnt
                FROM packages p
                LEFT JOIN versions v ON p.id = v.package_id
                LEFT JOIN findings f ON v.id = f.version_id
                GROUP BY p.id
            ) sub
        )
        SELECT finding_range, COUNT(*) as package_count
        FROM ranges
        GROUP BY finding_range
        ORDER BY 
            CASE finding_range
                WHEN '0' THEN 1
                WHEN '1-5' THEN 2
                WHEN '6-10' THEN 3
                WHEN '11-50' THEN 4
                ELSE 5
            END;
        """
        dist_df = run_query(dist_query)
        fig_dist = px.bar(dist_df, x='finding_range', y='package_count', title='Packages by Finding Count')
        st.plotly_chart(fig_dist, use_container_width=True)

with tab6:
    st.header("⚙️ Configuration Settings")
    st.markdown("Edit scan.yml settings and save changes")
    
    SCAN_YML_PATH = Path(__file__).resolve().parents[1] / 'scan.yml'
    
    try:
        with open(SCAN_YML_PATH, 'r') as f:
            config = yaml.safe_load(f)
    except Exception as e:
        st.error(f"Could not load scan.yml: {e}")
        config = {}
    
    if config:
        col_a, col_b = st.columns(2)
        
        with col_a:
            st.subheader("Allow Domains")
            st.caption("Trusted domains that won't trigger 'url_outside_allowlist' findings")
            
            allow_domains = config.get('analysis', {}).get('allow_domains', [])
            
            # Edit existing
            new_domains = st.text_area(
                "Allowed domains (one per line)",
                value="\n".join(allow_domains),
                height=200,
                help="Add domains like: registry.npmjs.org, github.com, mycdn.com"
            )
            
            st.markdown("---")
            
            st.subheader("Scoring Thresholds")
            current_scoring = config.get('scoring', {})
            thresholds = current_scoring.get('thresholds', {'suspicious': 7, 'malicious': 12})
            
            suspicious_threshold = st.number_input(
                "Suspicious Threshold",
                min_value=1,
                max_value=50,
                value=thresholds.get('suspicious', 7),
                help="Minimum score to mark as suspicious"
            )
            
            malicious_threshold = st.number_input(
                "Malicious Threshold",
                min_value=1,
                max_value=50,
                value=thresholds.get('malicious', 12),
                help="Minimum score to mark as malicious"
            )
        
        with col_b:
            st.subheader("Build Tool Allowlist")
            st.caption("Commands recognized as benign build steps (regex patterns)")
            
            build_tools = config.get('analysis', {}).get('allowlist', {}).get('build_tools', [])
            
            new_build_tools = st.text_area(
                "Build tool patterns (one per line)",
                value="\n".join(build_tools),
                height=200,
                help="Add regex patterns like: \\bnode-gyp\\b, \\btsc\\b"
            )
            
            st.markdown("---")
            
            st.subheader("Rule Weights")
            st.caption("Point values for each rule type")
            
            weights = current_scoring.get('rule_weights', {})
            
            col_w1, col_w2 = st.columns(2)
            with col_w1:
                lifecycle_exec = st.number_input("lifecycle_exec", 0, 20, weights.get('lifecycle_exec', 4))
                network_ioc = st.number_input("network_ioc", 0, 20, weights.get('network_ioc', 5))
                obfuscation = st.number_input("obfuscation", 0, 20, weights.get('obfuscation', 3))
                env_access = st.number_input("env_access", 0, 20, weights.get('env_access', 4))
                c2_webhook = st.number_input("c2_webhook", 0, 20, weights.get('c2_webhook', 6))
            
            with col_w2:
                writes_outside_pkg = st.number_input("writes_outside_pkg", 0, 20, weights.get('writes_outside_pkg', 6))
                suspicious_strings = st.number_input("suspicious_strings", 0, 20, weights.get('suspicious_strings', 2))
                native_payload = st.number_input("native_payload", 0, 20, weights.get('native_payload', 3))
                packed_bundle = st.number_input("packed_bundle", 0, 20, weights.get('packed_bundle', 2))
                new_bin_added = st.number_input("new_bin_added", 0, 20, weights.get('new_bin_added', 1))
        
        st.markdown("---")
        
        if st.button("💾 Save Changes to scan.yml", type="primary"):
            # Update config
            if 'analysis' not in config:
                config['analysis'] = {}
            if 'allowlist' not in config['analysis']:
                config['analysis']['allowlist'] = {}
            
            config['analysis']['allow_domains'] = [d.strip() for d in new_domains.split('\n') if d.strip()]
            config['analysis']['allowlist']['build_tools'] = [b.strip() for b in new_build_tools.split('\n') if b.strip()]
            
            if 'scoring' not in config:
                config['scoring'] = {}
            if 'thresholds' not in config['scoring']:
                config['scoring']['thresholds'] = {}
            if 'rule_weights' not in config['scoring']:
                config['scoring']['rule_weights'] = {}
            
            config['scoring']['thresholds']['suspicious'] = suspicious_threshold
            config['scoring']['thresholds']['malicious'] = malicious_threshold
            
            config['scoring']['rule_weights']['lifecycle_exec'] = lifecycle_exec
            config['scoring']['rule_weights']['network_ioc'] = network_ioc
            config['scoring']['rule_weights']['obfuscation'] = obfuscation
            config['scoring']['rule_weights']['env_access'] = env_access
            config['scoring']['rule_weights']['c2_webhook'] = c2_webhook
            config['scoring']['rule_weights']['writes_outside_pkg'] = writes_outside_pkg
            config['scoring']['rule_weights']['suspicious_strings'] = suspicious_strings
            config['scoring']['rule_weights']['native_payload'] = native_payload
            config['scoring']['rule_weights']['packed_bundle'] = packed_bundle
            config['scoring']['rule_weights']['new_bin_added'] = new_bin_added
            
            try:
                with open(SCAN_YML_PATH, 'w') as f:
                    yaml.dump(config, f, default_flow_style=False, sort_keys=False)
                st.success("✅ Saved to scan.yml! Re-run the analyzer to apply changes.")
            except Exception as e:
                st.error(f"Failed to save: {e}")

st.sidebar.title("About PackageInferno")
st.sidebar.info("""
**PackageInferno** scans npm packages for supply-chain threats:
- Lifecycle script analysis
- Obfuscation detection  
- child_process usage
- Base64 blob detection
- Binary discovery
- Version change tracking

Data stored in S3 + local Postgres.
""")

# Recent activity stats
recent_query = """
SELECT 
    COUNT(DISTINCT p.id) as packages_today,
    COUNT(DISTINCT v.id) as versions_today
FROM versions v
JOIN packages p ON v.package_id = p.id
WHERE v.analyzed_at >= CURRENT_DATE;
"""
try:
    recent = run_query(recent_query)
    st.sidebar.metric("Analyzed Today", recent['versions_today'][0] if len(recent) > 0 else 0)
except:
    pass

total_s3 = st.sidebar.empty()
try:
    import boto3
    s3 = boto3.client('s3')
    resp = s3.list_objects_v2(Bucket='package-inferno-findings', Prefix='npm-findings/')
    count = resp.get('KeyCount', 0)
    total_s3.metric("S3 Findings Uploaded", count)
except:
    pass

# Version changes (new releases detected)
st.sidebar.markdown("### 🆕 Recent Version Changes")
version_changes_query = """
SELECT p.name, COUNT(DISTINCT v.version) as version_count
FROM packages p
JOIN versions v ON p.id = v.package_id
GROUP BY p.name
HAVING COUNT(DISTINCT v.version) > 1
ORDER BY version_count DESC
LIMIT 5;
"""
try:
    vc = run_query(version_changes_query)
    if len(vc) > 0:
        st.sidebar.dataframe(vc, use_container_width=True, hide_index=True)
except:
    pass

