#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2012:140. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(61985);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/06/01 00:27:16 $");

  script_cve_id("CVE-2012-3382");
  script_bugtraq_id(54344);
  script_xref(name:"MDVSA", value:"2012:140");

  script_name(english:"Mandriva Linux Security Advisory : mono (MDVSA-2012:140)");
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
"A vulnerability has been discovered and corrected in mono :

Cross-site scripting (XSS) vulnerability in the ProcessRequest
function in mcs/class/System.Web/System.Web/HttpForbiddenHandler.cs in
Mono 2.10.8 and earlier allows remote attackers to inject arbitrary
web script or HTML via a file with a crafted name and a forbidden
extension, which is not properly handled in an error message
(CVE-2012-3382).

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mono-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mono0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mono2.0_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmono-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmono0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmono2.0_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-data-2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-data-4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-data-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-extras-2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-extras-4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-extras-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-locale-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-locale-extras-2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-locale-extras-4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-locale-extras-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-nunit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-wcf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-wcf-2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-wcf-4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-web-2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-web-4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-web-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-winforms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-winforms-2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-winforms-4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-winforms-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-winfxcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-winfxcore-2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-winfxcore-4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:monodoc-core");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2011");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64mono-devel-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64mono0-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64mono2.0_1-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libmono-devel-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libmono0-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libmono2.0_1-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-2.0-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-4.0-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-compat-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-data-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-data-2.0-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-data-4.0-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-data-compat-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-doc-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-extras-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-extras-2.0-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-extras-4.0-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-extras-compat-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-locale-extras-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-locale-extras-2.0-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-locale-extras-4.0-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-locale-extras-compat-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-nunit-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-wcf-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-wcf-2.0-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-wcf-4.0-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-web-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-web-2.0-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-web-4.0-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-web-compat-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-winforms-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-winforms-2.0-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-winforms-4.0-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-winforms-compat-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-winfxcore-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-winfxcore-2.0-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"mono-winfxcore-4.0-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"monodoc-core-2.10.2-4.1-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
