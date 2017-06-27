#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:109. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(82362);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/07 13:40:41 $");

  script_cve_id("CVE-2015-0219", "CVE-2015-0220", "CVE-2015-0221", "CVE-2015-0222", "CVE-2015-2241", "CVE-2015-2316", "CVE-2015-2317");
  script_xref(name:"MDVSA", value:"2015:109");

  script_name(english:"Mandriva Linux Security Advisory : python-django (MDVSA-2015:109)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated python-django packages fix security vulnerabilities :

Jedediah Smith discovered that Django incorrectly handled underscores
in WSGI headers. A remote attacker could possibly use this issue to
spoof headers in certain environments (CVE-2015-0219).

Mikko Ohtamaa discovered that Django incorrectly handled user-supplied
redirect URLs. A remote attacker could possibly use this issue to
perform a cross-site scripting attack (CVE-2015-0220).

Alex Gaynor discovered that Django incorrectly handled reading files
in django.views.static.serve(). A remote attacker could possibly use
this issue to cause Django to consume resources, resulting in a denial
of service (CVE-2015-0221).

Keryn Knight discovered that Django incorrectly handled forms with
ModelMultipleChoiceField. A remote attacker could possibly use this
issue to cause a large number of SQL queries, resulting in a database
denial of service. Note that this issue only affected python-django
(CVE-2015-0222).

Cross-site scripting (XSS) vulnerability in the contents function in
admin/helpers.py in Django before 1.7.6 and 1.8 before 1.8b2 allows
remote attackers to inject arbitrary web script or HTML via a model
attribute in ModelAdmin.readonly_fields, as demonstrated by a
\@property (CVE-2015-2241).

The utils.html.strip_tags function in Django 1.6.x before 1.6.11,
1.7.x before 1.7.7, and 1.8.x before 1.8c1, when using certain
versions of Python, allows remote attackers to cause a denial of
service (infinite loop) by increasing the length of the input string
(CVE-2015-2316).

The utils.http.is_safe_url function in Django before 1.4.20, 1.5.x,
1.6.x before 1.6.11, 1.7.x before 1.7.7, and 1.8.x before 1.8c1 does
not properly validate URLs, which allows remote attackers to conduct
cross-site scripting (XSS) attacks via a control character in a URL,
as demonstrated by a \x08javascript: URL (CVE-2015-2317)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2015-0026.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2015-0127.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-django-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-django-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python3-django");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS2", reference:"python-django-1.7.7-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"python-django-bash-completion-1.7.7-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"python-django-doc-1.7.7-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"python3-django-1.7.7-1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
