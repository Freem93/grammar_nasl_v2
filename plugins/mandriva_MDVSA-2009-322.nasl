#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:322. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(43041);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/28 21:39:23 $");

  script_cve_id("CVE-2007-5197", "CVE-2008-3422", "CVE-2008-3906", "CVE-2009-0217");
  script_bugtraq_id(26279, 35671);
  script_xref(name:"MDVSA", value:"2009:322");

  script_name(english:"Mandriva Linux Security Advisory : mono (MDVSA-2009:322)");
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
"Multiple vulnerabilities has been found and corrected in mono :

IOActive Inc. found a buffer overflow in Mono.Math.BigInteger class in
Mono 1.2.5.1 and previous versions, which allows arbitrary code
execution by context-dependent attackers (CVE-2007-5197).

Multiple cross-site scripting (XSS) vulnerabilities in the ASP.net
class libraries in Mono 2.0 and earlier allow remote attackers to
inject arbitrary web script or HTML via crafted attributes related to
(1) HtmlControl.cs (PreProcessRelativeReference), (2) HtmlForm.cs
(RenderAttributes), (3) HtmlInputButton (RenderAttributes), (4)
HtmlInputRadioButton (RenderAttributes), and (5) HtmlSelect
(RenderChildren) (CVE-2008-3422).

CRLF injection vulnerability in Sys.Web in Mono 2.0 and earlier allows
remote attackers to inject arbitrary HTTP headers and conduct HTTP
response splitting attacks via CRLF sequences in the query string
(CVE-2008-3906).

The XML HMAC signature system did not correctly check certain lengths.
If an attacker sent a truncated HMAC, it could bypass authentication,
leading to potential privilege escalation (CVE-2009-0217).

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers

The updated packages have been patched to fix these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 79, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:jay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mono-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mono0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmono-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmono0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-bytefx-data-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-data-firebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-data-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-data-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-data-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-data-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-ibm-data-db2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-jscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-locale-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-nunit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-winforms");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", reference:"jay-1.2.5-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64mono-devel-1.2.5-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64mono0-1.2.5-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libmono-devel-1.2.5-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libmono0-1.2.5-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mono-1.2.5-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mono-bytefx-data-mysql-1.2.5-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mono-data-1.2.5-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mono-data-firebird-1.2.5-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mono-data-oracle-1.2.5-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mono-data-postgresql-1.2.5-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mono-data-sqlite-1.2.5-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mono-data-sybase-1.2.5-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mono-doc-1.2.5-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mono-extras-1.2.5-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mono-ibm-data-db2-1.2.5-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mono-jscript-1.2.5-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mono-locale-extras-1.2.5-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mono-nunit-1.2.5-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mono-web-1.2.5-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mono-winforms-1.2.5-2.1mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
