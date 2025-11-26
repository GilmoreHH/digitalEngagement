import os
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from simple_salesforce import Salesforce
from dotenv import load_dotenv

load_dotenv()

# Page config
st.set_page_config(
    page_title="HH Insurance - Messaging Credits Dashboard",
    page_icon="💬",
    layout="wide"
)

# AUTHENTICATION IMPORT - Add this line
from magic_link_auth import require_auth, init_session_state

# INITIALIZE AUTHENTICATION - Add this line
init_session_state()


@st.cache_resource
def get_salesforce_connection():
    """Create cached Salesforce connection"""
    username = os.getenv('SALESFORCE_USERNAME_PROD')
    password = os.getenv('SALESFORCE_PASSWORD_PROD')
    security_token = os.getenv('SALESFORCE_SECURITY_TOKEN_PROD')
    return Salesforce(username=username, password=password, security_token=security_token, domain='login')


@st.cache_data(ttl=300)
def get_all_entitlements(_sf):
    """Get ALL entitlements from TenantUsageEntitlement"""
    query = """
        SELECT Id, ResourceGroupKey, AmountUsed, CurrentAmountAllowed,
               EndDate, Frequency, MasterLabel, StartDate, UsageDate,
               HasRollover, IsPersistentResource, OverageGrace, Setting
        FROM TenantUsageEntitlement
    """
    result = _sf.query_all(query)
    return result['records']


@st.cache_data(ttl=300)
def get_messaging_sessions_full(_sf, start_date=None, end_date=None, days=30):
    """Get ALL fields from messaging sessions"""
    if start_date and end_date:
        date_filter = f"CreatedDate >= {start_date}T00:00:00Z AND CreatedDate <= {end_date}T23:59:59Z"
    else:
        date_filter = f"CreatedDate >= LAST_N_DAYS:{days}"

    query = f"""
        SELECT Id, Name, Status, ChannelType, ChannelName, ChannelKey,
               MessagingChannelId, MessagingEndUserId,
               StartTime, EndTime, AcceptTime, Origin, AgentType,
               EndUserMessageCount, AgentMessageCount,
               OwnerId, Owner.Name, Owner.Email, Owner.Profile.Name,
               TargetUserId, ChannelGroup, ChannelIntent, ChannelLocale,
               ConversationId, EndUserAccountId, EndUserContactId,
               PreviewDetails, CreatedDate, LastModifiedDate,
               CreatedById, CreatedBy.Name
        FROM MessagingSession
        WHERE {date_filter}
        ORDER BY CreatedDate DESC
    """
    result = _sf.query_all(query)
    return result['records']


@st.cache_data(ttl=300)
def get_messaging_end_users(_sf, start_date=None, end_date=None, days=30):
    """Get messaging end user details"""
    if start_date and end_date:
        date_filter = f"CreatedDate >= {start_date}T00:00:00Z AND CreatedDate <= {end_date}T23:59:59Z"
    else:
        date_filter = f"CreatedDate >= LAST_N_DAYS:{days}"

    query = f"""
        SELECT Id, Name, MessagingChannelId, MessageType, MessagingPlatformKey,
               Locale, IsoCountryCode, MessagingConsentStatus, IsFullyOptedIn,
               OwnerId, Owner.Name, CreatedDate, LastModifiedDate
        FROM MessagingEndUser
        WHERE {date_filter}
        ORDER BY CreatedDate DESC
    """
    result = _sf.query_all(query)
    return result['records']


@st.cache_data(ttl=300)
def get_conversation_entries_full(_sf, start_date=None, end_date=None, days=30):
    """Get detailed conversation entries"""
    if start_date and end_date:
        date_filter = f"CreatedDate >= {start_date}T00:00:00Z AND CreatedDate <= {end_date}T23:59:59Z"
    else:
        date_filter = f"CreatedDate >= LAST_N_DAYS:{days}"

    query = f"""
        SELECT Id, ConversationId, EntryType, ActorType, ActorName,
               Message, MessageStatus, EntryTime, MessageSendTime,
               MessageDeliverTime, MessageReadTime, HasAttachments,
               CreatedDate, CreatedById
        FROM ConversationEntry
        WHERE {date_filter}
        ORDER BY CreatedDate DESC
        LIMIT 5000
    """
    result = _sf.query_all(query)
    return result['records']


@st.cache_data(ttl=300)
def get_messaging_channels(_sf):
    """Get all configured messaging channels with full details"""
    query = """
        SELECT Id, DeveloperName, MasterLabel, MessageType, PlatformType,
               IsActive, RoutingType, Description, ChannelAddressIdentifier,
               ConsentType, IsRequireDoubleOptIn, IsRestrictedToBusinessHours,
               TargetQueueId, BusinessHoursId
        FROM MessagingChannel
    """
    result = _sf.query_all(query)
    return result['records']


@st.cache_data(ttl=300)
def get_conversation_stats(_sf, start_date=None, end_date=None, days=30):
    """Get conversation statistics"""
    if start_date and end_date:
        date_filter = f"CreatedDate >= {start_date}T00:00:00Z AND CreatedDate <= {end_date}T23:59:59Z"
    else:
        date_filter = f"CreatedDate >= LAST_N_DAYS:{days}"

    queries = {}

    # By day
    queries['by_day'] = f"""
        SELECT DAY_ONLY(CreatedDate) day, COUNT(Id) cnt
        FROM MessagingSession
        WHERE {date_filter}
        GROUP BY DAY_ONLY(CreatedDate)
        ORDER BY DAY_ONLY(CreatedDate) DESC
    """

    # By hour of day
    queries['by_hour'] = f"""
        SELECT HOUR_IN_DAY(CreatedDate) hour, COUNT(Id) cnt
        FROM MessagingSession
        WHERE {date_filter}
        GROUP BY HOUR_IN_DAY(CreatedDate)
        ORDER BY HOUR_IN_DAY(CreatedDate)
    """

    # By status
    queries['by_status'] = f"""
        SELECT Status, COUNT(Id) cnt
        FROM MessagingSession
        WHERE {date_filter}
        GROUP BY Status
    """

    # By origin
    queries['by_origin'] = f"""
        SELECT Origin, COUNT(Id) cnt
        FROM MessagingSession
        WHERE {date_filter}
        GROUP BY Origin
    """

    results = {}
    for key, query in queries.items():
        try:
            result = _sf.query_all(query)
            results[key] = result['records']
        except:
            results[key] = []

    return results


@st.cache_data(ttl=300)
def get_messaging_delivery_errors(_sf, start_date=None, end_date=None, days=30):
    """Get messaging delivery errors"""
    if start_date and end_date:
        date_filter = f"CreatedDate >= {start_date}T00:00:00Z AND CreatedDate <= {end_date}T23:59:59Z"
    else:
        date_filter = f"CreatedDate >= LAST_N_DAYS:{days}"

    query = f"""
        SELECT Id, ErrorCode, ErrorMessage, MessagingSessionId,
               CreatedDate, CreatedById
        FROM MessagingDeliveryError
        WHERE {date_filter}
        ORDER BY CreatedDate DESC
        LIMIT 500
    """
    try:
        result = _sf.query_all(query)
        return result['records']
    except:
        return []

# Require authentication for the dashboard
@require_auth
def main():
    # Header
    st.title("📊 Digital Engagement / Messaging Credits Dashboard")
    st.markdown("**HH Insurance Group** - Comprehensive Usage Metrics for Contract Renewal")
    st.markdown("---")

    # Connect to Salesforce
    try:
        sf = get_salesforce_connection()
        st.success("✅ Connected to Salesforce Production")
    except Exception as e:
        st.error(f"❌ Failed to connect to Salesforce: {e}")
        return

    # Sidebar
    st.sidebar.header("📅 Dashboard Settings")
    date_option = st.sidebar.radio("Date Range Type", ["Preset", "Custom"])

    if date_option == "Preset":
        days = st.sidebar.selectbox("Select Range", [7, 14, 30, 60, 90], index=2)
        start_date = None
        end_date = None
    else:
        col1, col2 = st.sidebar.columns(2)
        with col1:
            start_date = st.date_input("Start Date", datetime.now() - timedelta(days=30))
        with col2:
            end_date = st.date_input("End Date", datetime.now())

        if start_date and end_date:
            days = (end_date - start_date).days
            if days <= 0:
                st.sidebar.error("End date must be after start date")
                days = 30

    st.sidebar.markdown("---")
    st.sidebar.header("📋 Navigation")
    page = st.sidebar.radio("Go to", [
        "Overview",
        "Credit Usage",
        "Session Analytics",
        "Agent Performance",
        "Channel Analysis",
        "Message Details",
        "End Users",
        "Errors & Issues",
        "Raw Data Export"
    ])

    st.sidebar.markdown("---")
    if st.sidebar.button("🔄 Refresh All Data"):
        st.cache_data.clear()
        st.rerun()

    # Convert dates to string format for queries
    start_date_str = str(start_date) if start_date else None
    end_date_str = str(end_date) if end_date else None

    # Load data
    with st.spinner("Loading data from Salesforce..."):
        all_entitlements = get_all_entitlements(sf)
        sessions = get_messaging_sessions_full(sf, start_date_str, end_date_str, days)
        channels = get_messaging_channels(sf)
        conv_stats = get_conversation_stats(sf, start_date_str, end_date_str, days)

    # Filter messaging entitlements
    messaging_entitlements = [e for e in all_entitlements
                             if e.get('MasterLabel') and
                             ('Messaging' in e.get('MasterLabel', '') or
                              'Chatbot' in e.get('MasterLabel', ''))]

    # ================================================================
    # PAGE: OVERVIEW
    # ================================================================
    if page == "Overview":
        st.header("🎯 Executive Overview")

        # Key metrics row
        col1, col2, col3, col4 = st.columns(4)

        total_sessions = len(sessions)
        total_end_user_msgs = sum(s.get('EndUserMessageCount') or 0 for s in sessions)
        total_agent_msgs = sum(s.get('AgentMessageCount') or 0 for s in sessions)
        active_channels = len([c for c in channels if c.get('IsActive')])

        col1.metric("Total Sessions", f"{total_sessions:,}", f"Last {days} days")
        col2.metric("Customer Messages", f"{total_end_user_msgs:,}")
        col3.metric("Agent Messages", f"{total_agent_msgs:,}")
        col4.metric("Active Channels", active_channels)

        st.markdown("---")

        # Credit usage summary
        st.subheader("💳 Credit Consumption Summary")

        agent_conv = next((e for e in messaging_entitlements if 'Agent Conversations' in (e.get('MasterLabel') or '')), None)
        blast_conv = next((e for e in messaging_entitlements if 'Blast Conversations' in (e.get('MasterLabel') or '')), None)

        col1, col2, col3 = st.columns(3)

        with col1:
            if agent_conv:
                used = agent_conv.get('AmountUsed', 0) or 0
                allowed = agent_conv.get('CurrentAmountAllowed', 0) or 0
                pct = (used / allowed * 100) if allowed > 0 else 0
                st.metric("Agent Conversations", f"{int(used):,} / {int(allowed):,}", f"{pct:.1f}% used")

                fig = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=used,
                    domain={'x': [0, 1], 'y': [0, 1]},
                    gauge={
                        'axis': {'range': [0, allowed]},
                        'bar': {'color': "darkblue"},
                        'steps': [
                            {'range': [0, allowed * 0.5], 'color': "lightgreen"},
                            {'range': [allowed * 0.5, allowed * 0.8], 'color': "yellow"},
                            {'range': [allowed * 0.8, allowed], 'color': "salmon"}
                        ]
                    }
                ))
                fig.update_layout(height=200, margin=dict(l=20, r=20, t=20, b=20))
                st.plotly_chart(fig, use_container_width=True)

        with col2:
            if blast_conv:
                used = blast_conv.get('AmountUsed', 0) or 0
                allowed = blast_conv.get('CurrentAmountAllowed', 0) or 0
                pct = (used / allowed * 100) if allowed > 0 else 0
                st.metric("Blast Conversations", f"{int(used):,} / {int(allowed):,}", f"{pct:.1f}% used")

                fig = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=used,
                    domain={'x': [0, 1], 'y': [0, 1]},
                    gauge={
                        'axis': {'range': [0, allowed]},
                        'bar': {'color': "purple"},
                        'steps': [
                            {'range': [0, allowed * 0.5], 'color': "lightgreen"},
                            {'range': [allowed * 0.5, allowed * 0.8], 'color': "yellow"},
                            {'range': [allowed * 0.8, allowed], 'color': "salmon"}
                        ]
                    }
                ))
                fig.update_layout(height=200, margin=dict(l=20, r=20, t=20, b=20))
                st.plotly_chart(fig, use_container_width=True)

        with col3:
            # Session trend mini chart
            if conv_stats.get('by_day'):
                df_trend = pd.DataFrame(conv_stats['by_day'])
                if not df_trend.empty:
                    df_trend = df_trend.sort_values('day')
                    fig = px.area(df_trend, x='day', y='cnt', title='Daily Sessions Trend')
                    fig.update_layout(height=250, showlegend=False)
                    st.plotly_chart(fig, use_container_width=True)

        st.markdown("---")

        # Quick stats
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("📊 Session Status Breakdown")
            if conv_stats.get('by_status'):
                df_status = pd.DataFrame(conv_stats['by_status'])
                if not df_status.empty:
                    fig = px.pie(df_status, values='cnt', names='Status', hole=0.4)
                    st.plotly_chart(fig, use_container_width=True)

        with col2:
            st.subheader("📱 Channel Distribution")
            by_channel = {}
            for s in sessions:
                ch = s.get('ChannelType') or s.get('ChannelName') or 'Unknown'
                by_channel[ch] = by_channel.get(ch, 0) + 1
            if by_channel:
                df_ch = pd.DataFrame([{'Channel': k, 'Sessions': v} for k, v in by_channel.items()])
                fig = px.pie(df_ch, values='Sessions', names='Channel', hole=0.4)
                st.plotly_chart(fig, use_container_width=True)

    # ================================================================
    # PAGE: CREDIT USAGE
    # ================================================================
    elif page == "Credit Usage":
        st.header("💳 Credit Usage Details")

        st.subheader("Messaging & Chatbot Entitlements")

        if messaging_entitlements:
            df_ent = pd.DataFrame([
                {
                    'Resource': e.get('MasterLabel', ''),
                    'Used': e.get('AmountUsed', 0) or 0,
                    'Allowed': e.get('CurrentAmountAllowed', 0) or 0,
                    'Usage %': ((e.get('AmountUsed', 0) or 0) / max((e.get('CurrentAmountAllowed', 1) or 1), 1) * 100),
                    'Frequency': e.get('Frequency', ''),
                    'Has Rollover': 'Yes' if e.get('HasRollover') else 'No',
                    'Persistent': 'Yes' if e.get('IsPersistentResource') else 'No',
                    'Start Date': str(e.get('StartDate', ''))[:10] if e.get('StartDate') else '',
                    'End Date': str(e.get('EndDate', ''))[:10] if e.get('EndDate') else '',
                    'Usage Date': str(e.get('UsageDate', ''))[:10] if e.get('UsageDate') else ''
                }
                for e in messaging_entitlements
            ])
            st.dataframe(df_ent, use_container_width=True)

            # Bar chart of usage
            fig = px.bar(df_ent, x='Resource', y='Usage %',
                        title='Credit Usage by Resource',
                        color='Usage %',
                        color_continuous_scale=['green', 'yellow', 'red'])
            fig.update_layout(xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)

        st.markdown("---")
        st.subheader("All Platform Entitlements")

        df_all = pd.DataFrame([
            {
                'Resource': e.get('MasterLabel', ''),
                'Used': e.get('AmountUsed', 0) or 0,
                'Allowed': e.get('CurrentAmountAllowed', 0) or 0,
                'Frequency': e.get('Frequency', ''),
                'Usage Date': str(e.get('UsageDate', ''))[:10] if e.get('UsageDate') else ''
            }
            for e in all_entitlements if e.get('CurrentAmountAllowed')
        ])
        st.dataframe(df_all, use_container_width=True)

    # ================================================================
    # PAGE: SESSION ANALYTICS
    # ================================================================
    elif page == "Session Analytics":
        st.header("📈 Session Analytics")

        # Daily trend
        st.subheader(f"Daily Sessions - Last {days} Days")
        if conv_stats.get('by_day'):
            df_day = pd.DataFrame(conv_stats['by_day']).sort_values('day')
            fig = px.bar(df_day, x='day', y='cnt', title='Sessions per Day')
            fig.update_layout(xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)

        col1, col2 = st.columns(2)

        with col1:
            # Hourly distribution
            st.subheader("Sessions by Hour of Day")
            if conv_stats.get('by_hour'):
                df_hour = pd.DataFrame(conv_stats['by_hour'])
                fig = px.bar(df_hour, x='hour', y='cnt', title='Peak Hours Analysis')
                fig.update_xaxes(tickmode='linear', dtick=1)
                st.plotly_chart(fig, use_container_width=True)

        with col2:
            # Origin breakdown
            st.subheader("Sessions by Origin")
            if conv_stats.get('by_origin'):
                df_origin = pd.DataFrame(conv_stats['by_origin'])
                fig = px.pie(df_origin, values='cnt', names='Origin')
                st.plotly_chart(fig, use_container_width=True)

        st.markdown("---")

        # Session duration analysis
        st.subheader("Session Duration Analysis")
        sessions_with_times = [s for s in sessions if s.get('StartTime') and s.get('EndTime')]
        if sessions_with_times:
            durations = []
            for s in sessions_with_times[:500]:  # Limit for performance
                try:
                    start = datetime.fromisoformat(s['StartTime'].replace('Z', '+00:00').replace('.000+0000', '+00:00'))
                    end = datetime.fromisoformat(s['EndTime'].replace('Z', '+00:00').replace('.000+0000', '+00:00'))
                    duration_mins = (end - start).total_seconds() / 60
                    if 0 < duration_mins < 480:  # Filter outliers (max 8 hours)
                        durations.append(duration_mins)
                except:
                    pass

            if durations:
                col1, col2, col3 = st.columns(3)
                col1.metric("Avg Duration", f"{sum(durations)/len(durations):.1f} min")
                col2.metric("Min Duration", f"{min(durations):.1f} min")
                col3.metric("Max Duration", f"{max(durations):.1f} min")

                fig = px.histogram(durations, nbins=30, title='Session Duration Distribution (minutes)')
                st.plotly_chart(fig, use_container_width=True)

    # ================================================================
    # PAGE: AGENT PERFORMANCE
    # ================================================================
    elif page == "Agent Performance":
        st.header("👤 Agent Performance")

        # Process by agent
        by_agent = {}
        for s in sessions:
            owner = s.get('Owner', {})
            if isinstance(owner, dict):
                name = owner.get('Name', 'Unknown')
                email = owner.get('Email', '')
                profile = owner.get('Profile', {})
                profile_name = profile.get('Name', '') if isinstance(profile, dict) else ''
            else:
                name, email, profile_name = 'Unknown', '', ''

            if name not in by_agent:
                by_agent[name] = {
                    'sessions': 0,
                    'end_user_msgs': 0,
                    'agent_msgs': 0,
                    'email': email,
                    'profile': profile_name
                }
            by_agent[name]['sessions'] += 1
            by_agent[name]['end_user_msgs'] += s.get('EndUserMessageCount') or 0
            by_agent[name]['agent_msgs'] += s.get('AgentMessageCount') or 0

        df_agents = pd.DataFrame([
            {
                'Agent': name,
                'Email': data['email'],
                'Profile': data['profile'],
                'Sessions': data['sessions'],
                'Customer Msgs': data['end_user_msgs'],
                'Agent Msgs': data['agent_msgs'],
                'Total Msgs': data['end_user_msgs'] + data['agent_msgs'],
                'Avg Msgs/Session': round((data['end_user_msgs'] + data['agent_msgs']) / max(data['sessions'], 1), 1)
            }
            for name, data in by_agent.items()
        ]).sort_values('Sessions', ascending=False)

        # Top metrics
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Agents Active", len(df_agents))
        col2.metric("Top Agent Sessions", df_agents.iloc[0]['Sessions'] if len(df_agents) > 0 else 0)
        col3.metric("Avg Sessions/Agent", f"{df_agents['Sessions'].mean():.1f}" if len(df_agents) > 0 else 0)

        st.markdown("---")

        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Sessions by Agent")
            fig = px.bar(df_agents.head(15), x='Agent', y='Sessions',
                        title='Top 15 Agents by Session Count',
                        color='Sessions', color_continuous_scale='Blues')
            fig.update_layout(xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            st.subheader("Messages by Agent")
            fig = px.bar(df_agents.head(15), x='Agent', y='Total Msgs',
                        title='Top 15 Agents by Message Count',
                        color='Total Msgs', color_continuous_scale='Greens')
            fig.update_layout(xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)

        st.markdown("---")
        st.subheader("Agent Detail Table")
        st.dataframe(df_agents, use_container_width=True)

    # ================================================================
    # PAGE: CHANNEL ANALYSIS
    # ================================================================
    elif page == "Channel Analysis":
        st.header("📱 Channel Analysis")

        st.subheader("Configured Messaging Channels")

        df_channels = pd.DataFrame([
            {
                'Channel Name': c.get('MasterLabel', ''),
                'Developer Name': c.get('DeveloperName', ''),
                'Type': c.get('MessageType', ''),
                'Platform': c.get('PlatformType', ''),
                'Status': '🟢 Active' if c.get('IsActive') else '🔴 Inactive',
                'Routing': c.get('RoutingType', ''),
                'Consent Type': c.get('ConsentType', ''),
                'Double Opt-In': 'Yes' if c.get('IsRequireDoubleOptIn') else 'No',
                'Business Hours Only': 'Yes' if c.get('IsRestrictedToBusinessHours') else 'No',
                'Address': c.get('ChannelAddressIdentifier', '')
            }
            for c in channels
        ])

        st.dataframe(df_channels, use_container_width=True)

        st.markdown("---")

        # Sessions by channel
        st.subheader("Session Volume by Channel")

        by_channel = {}
        for s in sessions:
            ch_type = s.get('ChannelType') or 'Unknown'
            ch_name = s.get('ChannelName') or ''
            key = f"{ch_type} ({ch_name})" if ch_name else ch_type
            if key not in by_channel:
                by_channel[key] = {'sessions': 0, 'msgs': 0}
            by_channel[key]['sessions'] += 1
            by_channel[key]['msgs'] += (s.get('EndUserMessageCount') or 0) + (s.get('AgentMessageCount') or 0)

        df_ch_usage = pd.DataFrame([
            {'Channel': k, 'Sessions': v['sessions'], 'Messages': v['msgs']}
            for k, v in by_channel.items()
        ])

        col1, col2 = st.columns(2)
        with col1:
            fig = px.pie(df_ch_usage, values='Sessions', names='Channel', title='Sessions by Channel')
            st.plotly_chart(fig, use_container_width=True)
        with col2:
            fig = px.pie(df_ch_usage, values='Messages', names='Channel', title='Messages by Channel')
            st.plotly_chart(fig, use_container_width=True)

    # ================================================================
    # PAGE: MESSAGE DETAILS
    # ================================================================
    elif page == "Message Details":
        st.header("💬 Message Details")

        with st.spinner("Loading conversation entries..."):
            entries = get_conversation_entries_full(sf, start_date_str, end_date_str, days)

        st.metric("Total Conversation Entries", f"{len(entries):,}", f"Last {days} days (max 5000)")

        # By actor type
        by_actor = {}
        for e in entries:
            actor = e.get('ActorType', 'Unknown')
            by_actor[actor] = by_actor.get(actor, 0) + 1

        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Messages by Actor Type")
            df_actor = pd.DataFrame([{'Actor': k, 'Count': v} for k, v in by_actor.items()])
            fig = px.pie(df_actor, values='Count', names='Actor')
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            st.subheader("Message Status Breakdown")
            by_status = {}
            for e in entries:
                status = e.get('MessageStatus', 'Unknown')
                by_status[status] = by_status.get(status, 0) + 1
            df_status = pd.DataFrame([{'Status': k, 'Count': v} for k, v in by_status.items()])
            fig = px.pie(df_status, values='Count', names='Status')
            st.plotly_chart(fig, use_container_width=True)

        st.markdown("---")

        # Messages with attachments
        with_attachments = len([e for e in entries if e.get('HasAttachments')])
        st.metric("Messages with Attachments", with_attachments)

        # Sample messages
        st.subheader("Recent Messages Sample")
        df_msgs = pd.DataFrame([
            {
                'Time': str(e.get('EntryTime', ''))[:19],
                'Actor': e.get('ActorType', ''),
                'Actor Name': e.get('ActorName', ''),
                'Type': e.get('EntryType', ''),
                'Status': e.get('MessageStatus', ''),
                'Message': (e.get('Message', '') or '')[:100] + '...' if len(e.get('Message', '') or '') > 100 else e.get('Message', '')
            }
            for e in entries[:100]
        ])
        st.dataframe(df_msgs, use_container_width=True)

    # ================================================================
    # PAGE: END USERS
    # ================================================================
    elif page == "End Users":
        st.header("👥 Messaging End Users")

        with st.spinner("Loading end user data..."):
            end_users = get_messaging_end_users(sf, start_date_str, end_date_str, days)

        st.metric("Messaging End Users", f"{len(end_users):,}", f"Created in last {days} days")

        # By consent status
        by_consent = {}
        for u in end_users:
            consent = u.get('MessagingConsentStatus', 'Unknown')
            by_consent[consent] = by_consent.get(consent, 0) + 1

        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Consent Status")
            df_consent = pd.DataFrame([{'Status': k, 'Count': v} for k, v in by_consent.items()])
            if not df_consent.empty:
                fig = px.pie(df_consent, values='Count', names='Status')
                st.plotly_chart(fig, use_container_width=True)

        with col2:
            st.subheader("Opt-In Status")
            opted_in = len([u for u in end_users if u.get('IsFullyOptedIn')])
            not_opted = len(end_users) - opted_in
            fig = px.pie(values=[opted_in, not_opted], names=['Opted In', 'Not Opted In'])
            st.plotly_chart(fig, use_container_width=True)

        # By message type
        st.subheader("By Message Type")
        by_type = {}
        for u in end_users:
            mtype = u.get('MessageType', 'Unknown')
            by_type[mtype] = by_type.get(mtype, 0) + 1
        df_type = pd.DataFrame([{'Type': k, 'Count': v} for k, v in by_type.items()])
        st.dataframe(df_type, use_container_width=True)

    # ================================================================
    # PAGE: ERRORS & ISSUES
    # ================================================================
    elif page == "Errors & Issues":
        st.header("⚠️ Errors & Delivery Issues")

        with st.spinner("Loading error data..."):
            errors = get_messaging_delivery_errors(sf, start_date_str, end_date_str, days)

        if errors:
            st.metric("Delivery Errors", len(errors), f"Last {days} days")

            # By error code
            by_code = {}
            for e in errors:
                code = e.get('ErrorCode', 'Unknown')
                by_code[code] = by_code.get(code, 0) + 1

            st.subheader("Errors by Code")
            df_errors = pd.DataFrame([{'Error Code': k, 'Count': v} for k, v in by_code.items()])
            fig = px.bar(df_errors, x='Error Code', y='Count', color='Count')
            st.plotly_chart(fig, use_container_width=True)

            # Error details
            st.subheader("Error Details")
            df_err_detail = pd.DataFrame([
                {
                    'Date': str(e.get('CreatedDate', ''))[:19],
                    'Error Code': e.get('ErrorCode', ''),
                    'Message': e.get('ErrorMessage', ''),
                    'Session ID': e.get('MessagingSessionId', '')
                }
                for e in errors[:50]
            ])
            st.dataframe(df_err_detail, use_container_width=True)
        else:
            st.success("✅ No delivery errors found in the selected period!")

    # ================================================================
    # PAGE: RAW DATA EXPORT
    # ================================================================
    elif page == "Raw Data Export":
        st.header("📥 Export Raw Data")

        st.markdown("Download data for external analysis or reporting.")

        col1, col2, col3 = st.columns(3)

        with col1:
            st.subheader("Sessions Data")
            df_sessions = pd.DataFrame([
                {
                    'Session ID': s.get('Id', ''),
                    'Name': s.get('Name', ''),
                    'Status': s.get('Status', ''),
                    'Channel Type': s.get('ChannelType', ''),
                    'Channel Name': s.get('ChannelName', ''),
                    'Origin': s.get('Origin', ''),
                    'Agent Type': s.get('AgentType', ''),
                    'Owner': s.get('Owner', {}).get('Name', '') if isinstance(s.get('Owner'), dict) else '',
                    'End User Msgs': s.get('EndUserMessageCount', 0),
                    'Agent Msgs': s.get('AgentMessageCount', 0),
                    'Start Time': s.get('StartTime', ''),
                    'End Time': s.get('EndTime', ''),
                    'Created Date': s.get('CreatedDate', '')
                }
                for s in sessions
            ])
            csv = df_sessions.to_csv(index=False)
            st.download_button(
                "📊 Download Sessions CSV",
                csv,
                f"messaging_sessions_{datetime.now().strftime('%Y%m%d')}.csv",
                "text/csv"
            )
            st.caption(f"{len(df_sessions)} records")

        with col2:
            st.subheader("Agent Summary")
            by_agent = {}
            for s in sessions:
                owner = s.get('Owner', {})
                name = owner.get('Name', 'Unknown') if isinstance(owner, dict) else 'Unknown'
                if name not in by_agent:
                    by_agent[name] = {'sessions': 0, 'msgs': 0}
                by_agent[name]['sessions'] += 1
                by_agent[name]['msgs'] += (s.get('EndUserMessageCount') or 0) + (s.get('AgentMessageCount') or 0)

            df_agent_export = pd.DataFrame([
                {'Agent': k, 'Sessions': v['sessions'], 'Total Messages': v['msgs']}
                for k, v in by_agent.items()
            ])
            csv = df_agent_export.to_csv(index=False)
            st.download_button(
                "👤 Download Agent CSV",
                csv,
                f"agent_summary_{datetime.now().strftime('%Y%m%d')}.csv",
                "text/csv"
            )
            st.caption(f"{len(df_agent_export)} agents")

        with col3:
            st.subheader("Entitlements")
            df_ent_export = pd.DataFrame([
                {
                    'Resource': e.get('MasterLabel', ''),
                    'Used': e.get('AmountUsed', 0),
                    'Allowed': e.get('CurrentAmountAllowed', 0),
                    'Frequency': e.get('Frequency', ''),
                    'Usage Date': e.get('UsageDate', '')
                }
                for e in all_entitlements
            ])
            csv = df_ent_export.to_csv(index=False)
            st.download_button(
                "💳 Download Entitlements CSV",
                csv,
                f"entitlements_{datetime.now().strftime('%Y%m%d')}.csv",
                "text/csv"
            )
            st.caption(f"{len(df_ent_export)} entitlements")

    # Footer
    st.markdown("---")
    st.caption(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    main()

