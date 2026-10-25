# طلب «رائد» ليكون جهة مرقّمة

هذه إجابات النموذج التفصيلي الذي يرسله برنامج CVE بعد طلب المعلومات، مكتوبة بالإنجليزية كما يطلبها النموذج، ومعها ملاحظة عربية حيث يلزم. رقم الهاتف لا يُكتب هنا لأن المستودع عام، بل في النموذج نفسه.

## Organisation

| Field | Answer |
|---|---|
| Organisation name | Raed (رائد), an open Arabic vulnerability register at https://cve.3li.info |
| Short name (CVE Services) | `raed` |
| Country | Kuwait |
| Industry | Software and services, security research |
| CNA type | Researcher, Vulnerability Coordinator |
| Proposed Root | MITRE Top-Level Root (no Root covers the Arab region today) |
| Public contact | site@hotmail.com |
| Disclosure policy | https://cve.3li.info/security/ |
| Advisory location | https://cve.3li.info/advisories/ |
| security.txt | https://cve.3li.info/.well-known/security.txt |
| Source code | https://github.com/SiteQ8/Raed |

## Scope

> Vulnerabilities discovered by, or reported to and coordinated through, Raed in software and services whose primary interface is Arabic or which are developed in Arab states, unless covered by the scope of another CNA.

النطاق يقع على فجوة حقيقية، فلا توجد اليوم جهة مرقّمة واحدة في الدول العربية بين 559 جهة، والجملة الأخيرة تمنع التداخل مع الموردين الذين لهم جهات مرقّمة.

## Points of contact

| Order | Name | Email | Phone |
|---|---|---|---|
| Primary | Ali AlEnezi | site@hotmail.com | يُكتب في النموذج فقط |
| Secondary | يُسمّى قبل الإرسال | بريد فردي لا بريد مجموعة | لا يلزم |

## Why Raed

- Raed already reads every new CVE Record within the hour and publishes it in Arabic, so the team works with the CVE Record Format daily.
- CVE JSON 5 allows descriptions in any language provided an English one is present. Every record Raed publishes will carry a full Arabic description next to the English one, so Arabic reaches every tool that reads the CVE List.
- Each advisory is authored as a complete CVE JSON 5.2 record and validated against the official schema in the repository's tests before it can be published.
- The disclosure policy commits to acknowledging reports within three business days, deciding within ten, publishing within 90 days or on fix, and publishing the CVE Record within 24 hours of disclosing the ID (never later than 72, CNA Rules 4.5.1.3 and 4.5.1.4).

## Before sending

- [ ] Name the secondary point of contact.
- [ ] Decide whether to apply as the Raed project or under a registered company that runs it.
- [ ] Submit https://cveform.mitre.org/ choosing "Request Information on the CVE Numbering Program (CNA)".
- [ ] Offer three onboarding call dates at least three weeks ahead.
