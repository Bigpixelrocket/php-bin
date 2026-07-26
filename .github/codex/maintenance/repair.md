# Repair phase

Observable goal: remove the supplied deterministic failure fingerprint with a
minimal admitted patch at the exact admitted base commit.

Use the supplied sanitized failure evidence. Prove the named cause was removed
without weakening, deleting, skipping, or replacing any gate. Run every
requested advisory check. A repeated identical fingerprint, a new unrelated
failure, exhausted attempt budget, unadmitted edit, or required protected
change is NO-GO. Use no network and do not commit, push, merge, tag, or publish.
