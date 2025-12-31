# GitHub Copilot Instructions (Authoritative)

These instructions are **authoritative**. When generating, modifying, or suggesting code, Copilot **must follow them exactly** unless explicitly told otherwise.

---

## 1. Project & Tooling Standards (Always Enforced)

* **Always use `pyproject.toml`** for all project configuration.
* **Always use Hatch**:

  * Build backend: `hatchling`
  * Versioning: `hatch-vcs`
* **Never hardcode a version number** anywhere.
* Use the following tools exclusively:

  * **Testing:** `pytest`
  * **Linting & formatting:** `ruff`
  * Commit message based **Changelog management:** `git-cliff`
  * **Virtual environments:** `venv`
  * **Documentation:** `sphinx` with **Read the Docs** theme
* All generated files must be compatible with **Python packaging best practices**.

---

## 2. Coding Standards (Strict)

Copilot **must always**:

* Produce **PEP 8–compliant** code.
* Add **type hints to every function, method, and public attribute**.
* Use **Google-style docstrings** for:

  * Modules
  * Classes
  * Functions and methods
* Include **usage examples** in docstrings where meaningful.
* Write **modular, reusable code**.
* Follow **SOLID principles**.
* Prefer **clarity over cleverness**.
* Avoid premature optimization.
* Never introduce unused imports, dead code, or commented-out logic.

---

## 3. Testing Requirements

* **Every new feature or bug fix must include tests.**
* Tests must:

  * Use `pytest`
  * Be deterministic
  * Clearly assert behavior, not implementation
* Favor small, focused test cases.
* Name tests descriptively.

---

## 4. Versioning & Releases (Hatch-VCS — Authoritative)

This section is **non-negotiable**.

### Version Source

* Versions **must be derived from Git tags only**.
* `pyproject.toml` **must declare**:

  ```toml
  [project]
  dynamic = ["version"]

  [tool.hatch.version]
  source = "vcs"
  ```
* **Never** set a static version.

### Version Semantics

* Git tags **must be annotated** and follow:

  ```
  vX.Y.Z
  ```
* Untagged commits **must** produce:

  ```
  X.Y.(Z+1).devN
  ```
* Use **PEP 440–compliant** versions only.
* Prefer the **`guess-next-dev`** scheme.
* Every CI build **must produce a unique version**.
* Assume:

  * Publishing happens on **every commit or merge to `main`**
  * TestPyPI receives **all CI builds**

### CI & GitHub Actions

* `actions/checkout` **must use**:

  ```yaml
  fetch-depth: 0
  ```
* Versioning must behave **identically** in:

  * Local builds
  * CI
  * GitHub Actions
* Publishing workflows **must never reuse a version number**.
* Optimize for **OIDC trusted publishing** (no API tokens).

---

## 5. Commit Message Rules (Conventional Commits — Enforced)

All commits **must** follow **Conventional Commits**.

### Format

```
<type>(<optional-scope>)<optional !>: <description>

[optional body]

[optional footers]
```

### Rules

* `feat` → **new user-visible features**
* `fix` → **bug fixes**
* Other allowed types: `docs`, `refactor`, `test`, `chore`, `ci`, `build`
* Scope:

  * Optional
  * Must be a noun
  * Example: `fix(parser):`
* Breaking changes:

  * Use `!` before the colon **OR**
  * Use a footer:

    ```
    BREAKING CHANGE: description
    ```
* `BREAKING CHANGE` **must be uppercase**.
* Footers must follow Git trailer conventions.
* Commit descriptions must be short, imperative, and clear.

---

## 6. Documentation Standards

Copilot must ensure:

* Documentation is structured into:

  * **Getting Started**
  * **User Guides**
  * **API Reference**
* All examples compile and match the current API.
* Terminology is consistent across:

  * Code
  * Docs
  * Docstrings
* Public APIs are always documented.

---

## 7. Default Behavior for Copilot

Unless explicitly instructed otherwise, Copilot should:

* Assume this is a **library**, not a script.
* Favor **public, documented APIs** over internal helpers.
* Generate code that is:

  * Testable
  * Lint-clean with `ruff`
  * Ready for CI
* Never bypass these rules “for convenience”.

---

**If any instruction conflicts with generated output, the instructions take precedence.**
