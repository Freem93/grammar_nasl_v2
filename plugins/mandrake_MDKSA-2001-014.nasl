#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2001:014. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(61888);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/05/31 23:43:25 $");

  script_cve_id("CVE-2001-1274", "CVE-2001-1275");
  script_xref(name:"MDKSA", value:"2001:014-1");

  script_name(english:"Mandrake Linux Security Advisory : MySQL (MDKSA-2001:014-1)");
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
"A security problem exists in all versions of MySQL after 3.23.2 and
prior to 3.23.31. The problem is that the SHOW GRANTS command could be
executed by any user making it possible for anyone with a MySQL
account to get the crypted password from the mysql.user table. The new
3.23.31 version fixes this.

Due to library changes, the previously announced PHP update
(MDKSA-2001:013) has been updated as well so that the php-mysql module
supports this new version of MySQL. It also corrects the upgrade
scripts in the package, however you will still need to verify that PHP
support is enabled in your /etc/httpd/conf/httpd.conf Apache
configuration file and verify that the installed modules are
uncommented in your /etc/php.ini file.

Update :

Previous versions of MySQL also suffered from a buffer overflow
problem that has been corrected in the recent releases. This update
fixes the buffer overflow problem in the MySQL packages provided with
Linux- Mandrake 7.1 and Corporate Server 1.0.1."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-shared");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-shared-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mod_php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-dba_gdbm_db2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-readline");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/01/26");
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
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"MySQL-3.22.32-5.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"MySQL-bench-3.22.32-5.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"MySQL-client-3.22.32-5.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"MySQL-devel-3.22.32-5.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"MySQL-shared-libs-3.22.32-5.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"MySQL-3.23.31-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"MySQL-bench-3.23.31-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"MySQL-client-3.23.31-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"MySQL-devel-3.23.31-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"MySQL-shared-3.23.31-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"mod_php-4.0.4pl1-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"php-4.0.4pl1-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"php-dba_gdbm_db2-4.0.4pl1-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"php-devel-4.0.4pl1-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"php-gd-4.0.4pl1-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"php-imap-4.0.4pl1-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"php-ldap-4.0.4pl1-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"php-manual-4.0.4pl1-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"php-mysql-4.0.4pl1-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"php-pgsql-4.0.4pl1-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"php-readline-4.0.4pl1-1.2mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
