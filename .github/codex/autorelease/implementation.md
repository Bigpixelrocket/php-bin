# Implementation phase

Observable goal: satisfy the admitted repository edit at the exact base commit,
within only the admitted paths, and leave a diff ready for deterministic
sealing and clean validation.

Use no web or shell network. Do not change a protected or unadmitted path. Run
every requested advisory check and record its command, exit status, and
evidence. Do not hide failed or unavailable checks. Return GO only when all
phase criteria passed, no in-scope work remains, and the diff stays within the
admitted authority. Do not commit, push, merge, tag, or publish.
