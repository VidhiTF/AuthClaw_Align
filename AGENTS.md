## Refactoring Protocol (Semantic Duplicates)

When a task involves "semantic duplicate" removal:

1. **AST Analysis**: For Python, use `ast` to compare function logical structures. For Go, use `ast/parser`.
2. **Cluster & Propose**: Do not refactor immediately. Print the identified cluster and ask: "I found this semantic match. Shall I merge into `backend/app/services/shared_utils.py`?"
3. **Normalization**: When merging, strip unique variable names and inline local configuration. Keep the "logical skeleton."
4. **Safety Check**: Before removing a duplicate, check if `pytest` or `go test` passes in both the original and destination files.
5. **Pointer Stability**: If merging shared logic, ensure the new utility function is idempotent and has no side effects.

## Line Budgets

| Path pattern | Max code lines |
| --- | ---: |
| `backend/app/*` | 10000 |
| `gateway/*` | 10000 |
| `audit_consumer/*` | 10000 |
| `console/src/*` | 10000 |
