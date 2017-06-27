#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:269. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(48155);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/09/02 15:06:43 $");

  script_cve_id("CVE-2009-0217");
  script_bugtraq_id(35671);
  script_xref(name:"MDVSA", value:"2009:269");

  script_name(english:"Mandriva Linux Security Advisory : mono (MDVSA-2009:269)");
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
"A vulnerability has been found and corrected in mono :

The XML HMAC signature system did not correctly check certain lengths.
If an attacker sent a truncated HMAC, it could bypass authentication,
leading to potential privilege escalation (CVE-2009-0217).

This update fixes this vulnerability."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-wcf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mono-winforms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:monodoc-core");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.1", reference:"jay-2.2-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64mono-devel-2.2-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64mono0-2.2-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libmono-devel-2.2-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libmono0-2.2-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mono-2.2-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mono-bytefx-data-mysql-2.2-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mono-data-2.2-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mono-data-firebird-2.2-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mono-data-oracle-2.2-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mono-data-postgresql-2.2-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mono-data-sqlite-2.2-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mono-data-sybase-2.2-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mono-doc-2.2-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mono-extras-2.2-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mono-ibm-data-db2-2.2-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mono-jscript-2.2-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mono-locale-extras-2.2-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mono-nunit-2.2-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mono-wcf-2.2-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mono-web-2.2-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mono-winforms-2.2-2.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"monodoc-core-2.2-2.1mdv2009.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
