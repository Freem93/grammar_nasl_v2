#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:028. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(20849);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/31 23:56:38 $");

  script_cve_id("CVE-2006-0207", "CVE-2006-0208");
  script_xref(name:"MDKSA", value:"2006:028");

  script_name(english:"Mandrake Linux Security Advisory : php (MDKSA-2006:028)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple response splitting vulnerabilities in PHP allow remote
attackers to inject arbitrary HTTP headers via unknown attack vectors,
possibly involving a crafted Set-Cookie header, related to the (1)
session extension (aka ext/session) and the (2) header function.
(CVE-2006-0207)

Multiple cross-site scripting (XSS) vulnerabilities in PHP allow
remote attackers to inject arbitrary web script or HTML via unknown
attack vectors in 'certain error conditions.' (CVE-2006-0208). This
issue does not affect Corporate Server 2.1.

Updated packages are patched to address these issues. Users must
execute 'service httpd restart' for the new PHP modules to be loaded
by Apache."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64php5_common5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64php_common432");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libphp5_common5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libphp_common432");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-fcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php432-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64php_common432-4.3.8-3.7.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libphp_common432-4.3.8-3.7.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"php-cgi-4.3.8-3.7.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"php-cli-4.3.8-3.7.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"php432-devel-4.3.8-3.7.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64php_common432-4.3.10-7.5.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libphp_common432-4.3.10-7.5.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"php-cgi-4.3.10-7.5.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"php-cli-4.3.10-7.5.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"php432-devel-4.3.10-7.5.102mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64php5_common5-5.0.4-9.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libphp5_common5-5.0.4-9.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"php-cgi-5.0.4-9.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"php-cli-5.0.4-9.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"php-devel-5.0.4-9.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"php-fcgi-5.0.4-9.3.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
