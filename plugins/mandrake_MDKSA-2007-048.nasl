#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:048. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(24695);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/28 21:39:21 $");

  script_cve_id("CVE-2007-0906", "CVE-2007-0907", "CVE-2007-0908", "CVE-2007-0909", "CVE-2007-0910", "CVE-2007-0988", "CVE-2007-1380");
  script_xref(name:"MDKSA", value:"2007:048");

  script_name(english:"Mandrake Linux Security Advisory : php (MDKSA-2007:048)");
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
"A number of vulnerabilities were discovered in PHP language.

Many buffer overflow flaws were discovered in the PHP session
extension, the str_replace() function, and the imap_mail_compose()
function. An attacker able to use a PHP application using any of these
functions could trigger these flaws and possibly execute arbitrary
code as the apache user (CVE-2007-0906).

A one-byte memory read will always occur prior to the beginning of a
buffer, which could be triggered, for example, by any use of the
header() function in a script (CVE-2007-0907).

The wddx extension, if used to import WDDX data from an untrusted
source, may allow a random portion of heap memory to be exposed due to
certain WDDX input packets (CVE-2007-0908).

The odbc_result_all() function, if used to display data from a
database, and if the contents of the database are under the control of
an attacker, could lead to the execution of arbitrary code due to a
format string vulnerability (CVE-2007-0909).

Several flaws in the PHP could allow attackers to clobber certain
super-global variables via unspecified vectors (CVE-2007-0910).

The zend_hash_init() function can be forced into an infinite loop if
unserializing untrusted data on a 64-bit platform, resulting in the
consumption of CPU resources until the script timeout alarm aborts the
execution of the script (CVE-2007-0988).

Updated package have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64php5_common5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libphp5_common5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-fcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-session");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64php5_common5-5.0.4-9.19.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libphp5_common5-5.0.4-9.19.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"php-cgi-5.0.4-9.19.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"php-cli-5.0.4-9.19.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"php-devel-5.0.4-9.19.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"php-fcgi-5.0.4-9.19.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"php-imap-5.0.4-2.5.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"php-odbc-5.0.4-1.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"php-session-5.0.4-1.1.20060mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64php5_common5-5.1.6-1.6mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libphp5_common5-5.1.6-1.6mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"php-cgi-5.1.6-1.6mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"php-cli-5.1.6-1.6mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"php-devel-5.1.6-1.6mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"php-fcgi-5.1.6-1.6mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"php-imap-5.1.6-1.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"php-odbc-5.1.6-1.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"php-session-5.1.6-1.1mdv2007.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
