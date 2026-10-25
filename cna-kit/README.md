# حزمة الطلب: نحو جهة ترقيم عربية

لا توجد حتى اليوم جهة مرقّمة (CNA) واحدة في الدول العربية ضمن برنامج CVE، وتضم هذه الحزمة ما تحتاجه أي جهة عربية لتتقدم، سواء كانت مورّداً أو فريق استجابة أو مشروع بحث، وكل ملف فيها بالعربية والإنجليزية لأن البرنامج يعمل بالإنجليزية بينما يقرأ المبلّغون العرب بلغتهم.

المرجع الحاكم هو [قواعد تشغيل الجهات المرقّمة في إصدارها 4.2.0](https://www.cve.org/Resources/Roles/Cnas/CNA_Rules_v4.2.0.pdf) النافذة منذ 25 أغسطس 2026، والإشارات بين قوسين في الملفات إلى أرقام أقسامها.

| الملف | الغرض |
|---|---|
| [disclosure-policy.ar.md](disclosure-policy.ar.md) | سياسة الإفصاح بالعربية بمدد رد محددة وفترة حظر تسعين يوماً |
| [disclosure-policy.en.md](disclosure-policy.en.md) | النص الإنجليزي المطابق للسياسة |
| [scope.md](scope.md) | بيان النطاق بثلاث صيغ للمورّد وفريق الاستجابة ومشروع البحث |
| [advisory-template.md](advisory-template.md) | نموذج نشرة أمنية يحقق متطلبات السجل في القسم الخامس من القواعد |
| [intake-form.md](intake-form.md) | حقول استقبال البلاغ التي يحتاجها السجل |
| [security.txt](security.txt) | ملف التواصل الأمني وفق المعيار RFC 9116 |

## طريقة الاستخدام

انسخ المجلد إلى مستودع جهتك، ثم استبدل كل ما بين القوسين المعقوفين مثل `{ORG_NAME}` ببيانات جهتك، ثم انشر سياسة الإفصاح وملف security.txt في عنوانين ثابتين، وبعد ذلك اتبع الخطوات المشروحة في صفحة الطريق إلى جهة ترقيم عربية https://cve.3li.info/cna/join/ حتى ترسل الطلب.

---

# Application kit: towards an Arab CNA

No CVE Numbering Authority exists yet in any Arab state. This kit holds what an Arab vendor, CERT or research project needs to apply, in Arabic and English, mapped to the CNA Operational Rules v4.2.0 (effective 25 August 2026). Replace every `{PLACEHOLDER}`, publish the policy and security.txt at stable URLs, then follow the steps at https://cve.3li.info/cna/join/.
