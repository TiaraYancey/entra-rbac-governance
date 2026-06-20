# Enterprise IAM Governance & Automated RBAC Engine (Microsoft Entra ID)

An automated Identity Governance and Administration (IGA) and Role-Based Access Control (RBAC) synchronization engine built in Python utilizing the Microsoft Graph SDK. This project automates the complete enterprise Joiner-Leaver identity lifecycle, dynamically provisioning users and mapping security group permissions based on authoritative HR attributes while maintaining an append-only compliance audit trail.

## 🚀 Architectural Overview

This governance framework implements a robust Zero-Trust identity architecture by eliminating manual administrative overhead, data configuration drift, and the risks associated with "privilege creep."

* **The Problem:** Manual onboarding delays productivity, while manual offboarding leaves orphan accounts vulnerable. Furthermore, manually managing security group assignments frequently results in users retaining access privileges long after changing roles or departments.
* **The Solution:** A centralized automation engine that evaluates HR source attributes in real-time, enforces directory integrity gates, assigns mandatory initial security baselines, and dynamically maps role permissions.

## 🛠️ Tech Stack & Dependencies
* **Core Language:** Python 3.x
* **Cloud API Layer:** Microsoft Graph Python SDK (`msgraph`)
* **Identity & Authentication:** Azure Identity SDK (`azure-identity`)
* **Environment Configuration:** `python-dotenv`
* **Data Layer:** Local Structured JSON (Simulating enterprise HRIS platforms like Workday/ADP)

## 📁 Repository Structure
```text
├── .env.example            # Deployment template for tenant configurations
├── employees.json          # Authoritative HR database (Attributes & Lifecycles)
├── identity_audit.log      # Append-only IT compliance audit trail (Generated at runtime)
├── sync_identities.py      # Core identity logic and RBAC engine
└── README.md               # System documentation
