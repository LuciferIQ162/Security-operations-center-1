# Quick Start Guide

Get your AI SOC Agent up and running in 5 minutes!

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

## Step 1: Install Dependencies

```bash
# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install packages
pip install -r requirements.txt
```

## Step 2: Configure (Optional)

Create a `.env` file if you want to customize settings:

```bash
cp .env.example .env
# Edit .env as needed
```

For basic testing, you can skip this step - defaults will work.

## Step 3: Run Tests

Test the agent with example alerts:

```bash
python test_agent.py
```

This will:
- Initialize the database
- Process 3 example alerts (EDR, Phishing, Low Risk)
- Show investigation results
- Demonstrate learning system

## Step 4: Start the API Server

```bash
python main.py
```

The API will start at `http://localhost:8000`

## Step 5: Test the API

### Using curl:

```bash
# Create an example alert
curl -X POST "http://localhost:8000/alerts/example"

# Get agent stats
curl "http://localhost:8000/stats"

# Get capabilities
curl "http://localhost:8000/capabilities"
```

### Using Python:

```python
import requests

# Create an alert
response = requests.post("http://localhost:8000/alerts", json={
    "title": "Suspicious Activity",
    "source": "edr",
    "severity": "high",
    "hostname": "workstation-01"
})

result = response.json()
print(f"Risk Score: {result['investigation']['risk_score']}")
print(f"Threat Severity: {result['conclusion']['threat_severity']}")
```

## Step 6: View API Documentation

Once the server is running, visit:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## Next Steps

1. **Integrate with your security tools**
   - Update `.env` with your EDR/SIEM endpoints
   - Modify `investigation_engine.py` to connect to real APIs

2. **Customize decision logic**
   - Edit `decision_maker.py` to adjust risk thresholds
   - Update `_load_policies()` with your security policies

3. **Enable learning**
   - Submit feedback via `/alerts/{id}/feedback` endpoint
   - Monitor improvements via `/stats` endpoint

4. **Scale up**
   - Adjust `MAX_PARALLEL_INVESTIGATIONS` in `.env`
   - Deploy to production with proper database (PostgreSQL, etc.)

## Troubleshooting

**Database errors?**
- Delete `soc_agent.db` and restart
- Check database permissions

**Import errors?**
- Make sure virtual environment is activated
- Run `pip install -r requirements.txt` again

**API not starting?**
- Check if port 8000 is available
- Change port in `.env` file

## Example Workflow

1. Security tool sends alert → `/alerts` endpoint
2. Agent classifies and investigates automatically
3. Agent makes decision and generates conclusion
4. Review conclusion via `/alerts/{id}`
5. Submit feedback via `/alerts/{id}/feedback`
6. Agent learns and improves over time

That's it! Your AI SOC Agent is ready to handle security alerts autonomously.
