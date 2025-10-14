# Verifier Selection & Management Page

**Audience:** Application developers who have already created one or more verifiers and want to review their configuration, audit them, test them with a PID, or move them to production.

The **Verifier Selection** page allows you to:

- View the list of your existing verifiers (either **Sandbox** or **Production**).  
- Check the key configuration data for each verifier (such as its API credentials and credential ID).  
- Perform actions such as **auditing**, **testing with PID**, **moving to production** (if subscribed), or deleting.  
- Create a new verifier when needed.

---

## Objective of the Page

The goal of this page is to give you a **clear overview of your verifier configurations** and allow you to quickly:

- Verify that your **Application API credentials** are correct.  
- Identify which client ID scheme and credential ID are associated with each verifier.  
- Run an **Audit** to confirm configuration is complete.  
- Launch a **basic PID test** to validate the verifier’s flow.  
- Promote a Sandbox verifier to **Production** (if your subscription allows).  
- Remove outdated or unused verifiers.

---

## Page Layout & Data Displayed

When you visit the page, you will see:

- **Page title** — depends on the verifier type:  
  - *Your Sandbox Verifiers* (test environment)  
  - *Your Production Verifiers* (live environment)  

- **Flashed messages** — any feedback from recent actions (e.g., “Verifier deleted successfully”).  

- **Create New Verifier button** — opens the form to configure a new verifier.  

- **Table of verifiers** — one row per verifier, with the following columns:  

  | Column              | Description |
  |---------------------|-------------|
  | **Name**            | The internal name of the verifier you set when creating it. |
  | **client_id**       | Your issued OIDC `client_id` for this verifier’s Application API (truncated for readability). |
  | **Credential ID**   | The credential identifier. If missing, it is highlighted in **red** as “None – To Be Updated”. |
  | **Client Id Scheme**| The client ID scheme associated with this verifier. |
  | **Actions**         | Buttons to manage this verifier (see below). |

If no verifiers exist, the table will show a message letting you know you don’t have any yet.

---

## Actions

Each verifier row contains the following possible actions:

- **Audit**  
  Runs a quick validation of the verifier’s configuration. Missing or invalid values (such as an absent Credential ID) will be highlighted. While the audit runs, a short “Auditing… please wait” message is displayed.  

- **Test (PID)**  
  Starts a test flow using a **basic PID credential**. This confirms that:  
  - The verifier is reachable.  
  - The configuration is valid.  
  - A wallet can complete the presentation flow successfully.  

- **Move to Production**  
  Available for Sandbox verifiers once they are validated and if your subscription allows. This action promotes the verifier into the live Production environment.  

- **Move to Sandbox**  
  For Production verifiers, you can move them back to Sandbox for safer testing.  

- **Update**  
  Opens the form to edit the verifier’s configuration.  

- **Delete**  
  Permanently removes the verifier after confirmation.  
  *Note:* This action cannot be undone.  

---

## Using the Page Effectively

1. **Create in Sandbox first** — Always start by creating and testing verifiers in Sandbox.  
2. **Audit before testing** — Run an audit to make sure configuration is complete and correct.  
3. **Test with PID** — Validate the end-to-end flow with a PID credential.  
4. **Promote carefully** — Only move verifiers to Production once you are satisfied they work as expected and your subscription allows it.  
5. **Update and re-audit** — After any change, audit and test again.  
6. **Clean up** — Remove unused verifiers to avoid confusion.  

---

## Security Note

- Only part of the `client_id` is displayed for safety. The full value is stored securely.  
- If you suspect credentials have been compromised, delete the verifier and create a new one.  
- Missing **Credential IDs** are highlighted in **red** so you can easily spot them.  

---

## Related Pages

- **verifier_create.md** — How to create and configure a new verifier.  
- **Verifier Display** — Full configuration details for a single verifier.  
- **Audit & Test** — End-to-end audit and PID testing.  
- **Subscriptions** — Details on enabling promotion to Production.  
