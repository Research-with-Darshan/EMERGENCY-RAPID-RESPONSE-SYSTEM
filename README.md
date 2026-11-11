# Emergency Rapid Response System (ERRS)

ERRS is a fictional educational  prototype created for the COMSM0122
system-security coursework. It demonstrates how an incident can be reported,
reviewed by authorised staff and passed to simulated emergency- response
services.

The prototype includes:

- Public  incident reporting with camera-captured images or videos
- Automatic browser location capture when permission is granted
- Public report tracking using either  a reference number or private token
- Human-led dispatcher  review and approval
- Simulated  ambulance, police and fire-service requests
- Demo vehicle allocation estimated arival times and public-safe updates
- Role-based staff access and authority- specific information sharing
- Audit records, information classificationand retention examples
- Consensus faulttolerance t eaching simulations

## Public users and staff access

This coursework  prototype contains  both public and staff areas in one
application so that the complete workflow can demonstrated easily.

### Public users

Public users can :

1. Open the public homepage .
2. Submit a demonstration report .
3. Capture supporting images or videos directly from the camera .
4. Allow the browserto provide their location.
5. Track a  report using either  its reference number or private access token.
6. See public safe status updates estimated arrival information and messages
   explaining  that the relevant  authority will contact them .

Public users  cannot access staff dashboards incident evidence datasets
audit records security controls or internal dispatch information.

### Authorised staff

Staff must  sign in through the staff login and are given access according to
their role.  Staff can only use the portal and records permitted for their role.
For example:

- **DISPATCHER** — r eviews incidents and allocates simulated resources
- **POLICE** — receives  police-related service requests
- **PARAMEDIC** — receives  ambulance-related service requests
- **FIRE** — receives fire-related s ervice requests
- **REGIONAL_COMMANDER** —  views authorised regional information
- **NATIONAL_COMMANDER** — views authorised national information
- **INTELLIGENCE_ANALYST** — works  with restricted intelligence functions
- **AUDITOR** — reviews audit and governance evidence

Opening a public page signs out  an active staff session. This prevents a staff
portal session from being carried into the public reporting or tracking
workflow.

### Real-world deployment model

In a real emergency system the  public reporting service and the staff
operations portal should be deployed as separate web applications. They
should use separate access controls authentication policies, network
boundaries a nd data views. This separation helps protect privileged staff
functions and prevents  public users from reaching confidential operational
information.

## Requirements

- Python  3.10 or newer
- pip

## Installation and running

Create and  activate a virtual environment:

```bash
python -m venv .venv

# macOS/Linux
source .venv/bin/activate

# Windows
.venv\Scripts\activate
```

Install the dependencies and start the application:

```bash
pip install -r requirements.txt
python run.py
```

Open the application at :

```text
http://127.0.0.1:5000
```

For anything beyond a  local demonstration, set a strong `SECRET_KEY`
environment variable . The default development key must not be used in a real
deployment .

## Creating staff accounts

Staff accounts are  created interactively.  Passwords are not hard-coded in the
application:

```bash
python manage.py create-user
```

The account  creator chooses the staff role and,  where required, a region:

- North
- Central
- South

Regional  commanders should be assigned to a region National accounts do not
need a region. Credentials must be stored securely.

## Demonstration workflow

1.  Open the public homepage and submit a fictional incident.
2. Capture  at least one demonstration image or video.
3. Save the  displayed  reference number and one-time private access token.
4. Sign in through the staff  login as a dispatcher.
5. Review the  submitted incident and move it through the permitted statuses.
6. Approve the required simulate d services.
7. Sign in using  the matching service role and respond to the request.
8. Return to the dispatcher portal  and allocate available demo vehicles.
9. View the public-safe updates  using the reference number or private token.
10. Use an auditor  account to inspect the hash-linked audit records.

## Coursework datasets

The source datasets  are stored in `data/source/`:

- `incidents.json`
- `responders.json`
- `intelligence.json`
- `dispatch.json`
- `audit.json`

Import them with:

```bash
python import_datasets.py
```

The  importer validates the JSON structure and record identifiers, preserves
the source records, records a SHA-256 file digest and can be safely rerun.
Dataset access is role controlled and  viewing a dataset is recorded in the
application audit  trail.

## Running tests

Run the test suite with :

```bash
pytest -q
```

Only report test r esults after running the command on  the current machine.

## Evidence generation

Consensus experiments can be run from  the security page. Their results are
written to `evidence/experiments/`.

To generate all nine  experiment logs  and the five governance scenarios without
using the browser:

```bash
python export_evidence.py
```

These are educational  simulations, not production implementations of
BFT, Paxos or Raft.

## Limitations

ERRS is a coursework prototype  and is not a deployable  emergency platform. It
uses SQLite,  simulated regions and fictional response  resources. It does not
provide:

- Real  emergency-service integration
- Real responder dispatch
- Production live vehicle tracking
- Multi-region failover
- Production- grade BFT, Paxos or  Raft
- Formal security  certification
- A production  deployment architecture

Before  submission run the tests,review the generated evidence,capture the
required screenshots and prepare the separate coursework report and assurance
portfolio PDFs.
