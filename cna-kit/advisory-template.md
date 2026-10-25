# نموذج النشرة الأمنية

يحقق هذا النموذج ما تطلبه القواعد في السجل (القسم الخامس)، أي رقم الثغرة والمنتج والإصدارات المصابة والوصف ونوع الضعف والأثر ومرجع عام واحد على الأقل لا يتطلب تسجيل الدخول، ويُنشر في موضع النشرات المعلن (القسم 4.5.2).

---

## {CVE_ID}: {TITLE_AR}

**تاريخ النشر:** {DATE}
**المنتج:** {PRODUCT}
**الإصدارات المصابة:** من {VERSION_FROM} حتى ما قبل {VERSION_FIXED}
**الإصدار الذي يصلح الثغرة:** {VERSION_FIXED}
**نوع الضعف:** {CWE_ID} ({CWE_NAME_AR})
**تقييم الخطورة:** {CVSS_SCORE} ({SEVERITY_AR})، والمتجه `{CVSS_VECTOR}`

### الوصف

{DESCRIPTION_AR}

### الأثر

{IMPACT_AR}

### الإصلاح

حدّث {PRODUCT} إلى الإصدار {VERSION_FIXED} أو أحدث، وإن تعذر التحديث فطبّق التخفيف التالي مؤقتاً: {WORKAROUND_AR}.

### الشكر

اكتشف الثغرة وأبلغ عنها {CREDIT}.

### المراجع

- سجل الثغرة: https://www.cve.org/CVERecord?id={CVE_ID}
- {OTHER_REFERENCES}

---

## {CVE_ID}: {TITLE}

**Published:** {DATE} · **Product:** {PRODUCT} · **Affected:** {VERSION_FROM} to before {VERSION_FIXED} · **Fixed in:** {VERSION_FIXED} · **CWE:** {CWE_ID} · **CVSS:** {CVSS_SCORE} `{CVSS_VECTOR}`

**Description.** {DESCRIPTION}

**Impact.** {IMPACT}

**Remediation.** Upgrade to {VERSION_FIXED} or later. If you cannot upgrade, {WORKAROUND}.

**Credit.** {CREDIT}

**References.** https://www.cve.org/CVERecord?id={CVE_ID}
