"""Test script for AI SOC Agent."""
import asyncio
import json
from agent import AISOCAgent
from database import init_db


async def test_agent():
    """Test the AI SOC Agent with example alerts."""
    # Initialize database
    await init_db()
    
    # Initialize agent
    agent = AISOCAgent()
    
    print("=" * 60)
    print("AI SOC Agent Test")
    print("=" * 60)
    
    # Test 1: EDR Alert
    print("\n[Test 1] Processing EDR Alert...")
    edr_alert = {
        "title": "Suspicious Process Execution Detected",
        "description": "Unusual process activity detected on endpoint",
        "source": "edr",
        "alert_type": "edr",
        "severity": "high",
        "user_id": "user123",
        "hostname": "workstation-01",
        "ip_address": "192.168.1.100",
        "raw_data": {
            "process_name": "suspicious.exe",
            "command_line": "suspicious.exe --stealth",
            "parent_process": "explorer.exe",
        }
    }
    
    result1 = await agent.process_alert(edr_alert)
    print(f"✓ Alert ID: {result1['alert']['id']}")
    print(f"✓ Risk Score: {result1['investigation']['risk_score']:.2f}/10")
    print(f"✓ Threat Severity: {result1['conclusion']['threat_severity']}")
    print(f"✓ Requires Human Review: {result1['conclusion']['requires_human_review']}")
    print(f"✓ Recommended Actions: {len(result1['conclusion']['recommended_actions'])}")
    
    # Test 2: Phishing Alert
    print("\n[Test 2] Processing Phishing Alert...")
    phishing_alert = {
        "title": "Suspicious Email Detected",
        "description": "Email contains suspicious links",
        "source": "email_security",
        "alert_type": "phishing",
        "severity": "medium",
        "user_id": "user456",
        "raw_data": {
            "sender": "suspicious@example.com",
            "subject": "Urgent: Verify Your Account",
            "urls": ["http://malicious-site.com/phish"],
        }
    }
    
    result2 = await agent.process_alert(phishing_alert)
    print(f"✓ Alert ID: {result2['alert']['id']}")
    print(f"✓ Risk Score: {result2['investigation']['risk_score']:.2f}/10")
    print(f"✓ Threat Severity: {result2['conclusion']['threat_severity']}")
    
    # Test 3: Low Risk Alert (likely false positive)
    print("\n[Test 3] Processing Low Risk Alert...")
    low_risk_alert = {
        "title": "Normal Administrative Activity",
        "description": "Standard system maintenance",
        "source": "siem",
        "alert_type": "network",
        "severity": "low",
        "hostname": "server-01",
        "raw_data": {
            "event_type": "admin_login",
            "user": "admin",
        }
    }
    
    result3 = await agent.process_alert(low_risk_alert)
    print(f"✓ Alert ID: {result3['alert']['id']}")
    print(f"✓ Risk Score: {result3['investigation']['risk_score']:.2f}/10")
    print(f"✓ Threat Severity: {result3['conclusion']['threat_severity']}")
    
    # Test 4: Get Agent Stats
    print("\n[Test 4] Getting Agent Statistics...")
    stats = await agent.get_agent_stats()
    print(f"✓ Active Investigations: {stats['active_investigations']}")
    print(f"✓ Autonomy Level: {stats['autonomy_level']}")
    print(f"✓ Learning Enabled: {stats['learning_enabled']}")
    
    if stats.get('learning_metrics'):
        print(f"✓ Total Investigations: {stats['learning_metrics']['total_investigations']}")
        print(f"✓ Accuracy: {stats['learning_metrics']['accuracy']:.2%}")
    
    # Test 5: Submit Feedback (for learning)
    print("\n[Test 5] Submitting Feedback for Learning...")
    feedback_result = await agent.record_feedback(
        result3['alert']['id'],
        "false_positive",
        "This was legitimate administrative activity"
    )
    print(f"✓ Feedback Status: {feedback_result['status']}")
    
    print("\n" + "=" * 60)
    print("All Tests Completed Successfully!")
    print("=" * 60)
    
    # Print detailed result for first alert
    print("\n[Detailed Result for Test 1]")
    print(json.dumps(result1, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(test_agent())
