#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0040 and 
# Oracle Linux Security Advisory ELSA-2010-0040 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67986);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/03/09 14:56:42 $");

  script_cve_id("CVE-2009-2687", "CVE-2009-3291", "CVE-2009-3292", "CVE-2009-3546", "CVE-2009-4017", "CVE-2009-4142");
  script_bugtraq_id(35440, 36449, 36712, 37079);
  script_osvdb_id(59071);
  script_xref(name:"RHSA", value:"2010:0040");

  script_name(english:"Oracle Linux 3 / 4 / 5 : php (ELSA-2010-0040)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0040 :

Updated php packages that fix several security issues are now
available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Web server.

Multiple missing input sanitization flaws were discovered in PHP's
exif extension. A specially crafted image file could cause the PHP
interpreter to crash or, possibly, disclose portions of its memory
when a PHP script tried to extract Exchangeable image file format
(Exif) metadata from the image file. (CVE-2009-2687, CVE-2009-3292)

A missing input sanitization flaw, leading to a buffer overflow, was
discovered in PHP's gd library. A specially crafted GD image file
could cause the PHP interpreter to crash or, possibly, execute
arbitrary code when opened. (CVE-2009-3546)

It was discovered that PHP did not limit the maximum number of files
that can be uploaded in one request. A remote attacker could use this
flaw to instigate a denial of service by causing the PHP interpreter
to use lots of system resources dealing with requests containing large
amounts of files to be uploaded. This vulnerability depends on file
uploads being enabled (which it is, in the default PHP configuration).
(CVE-2009-4017)

Note: This update introduces a new configuration option,
max_file_uploads, used for limiting the number of files that can be
uploaded in one request. By default, the limit is 20 files per
request.

It was discovered that PHP was affected by the previously published
'null prefix attack', caused by incorrect handling of NUL characters
in X.509 certificates. If an attacker is able to get a
carefully-crafted certificate signed by a trusted Certificate
Authority, the attacker could use the certificate during a
man-in-the-middle attack and potentially confuse PHP into accepting it
by mistake. (CVE-2009-3291)

It was discovered that PHP's htmlspecialchars() function did not
properly recognize partial multi-byte sequences for some multi-byte
encodings, sending them to output without them being escaped. An
attacker could use this flaw to perform a cross-site scripting attack.
(CVE-2009-4142)

All php users should upgrade to these updated packages, which contain
backported patches to resolve these issues. After installing the
updated packages, the httpd daemon must be restarted for the update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-January/001316.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-January/001318.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-January/001321.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-domxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"php-4.3.2-54.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"php-4.3.2-54.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"php-devel-4.3.2-54.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"php-devel-4.3.2-54.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"php-imap-4.3.2-54.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"php-imap-4.3.2-54.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"php-ldap-4.3.2-54.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"php-ldap-4.3.2-54.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"php-mysql-4.3.2-54.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"php-mysql-4.3.2-54.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"php-odbc-4.3.2-54.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"php-odbc-4.3.2-54.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"php-pgsql-4.3.2-54.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"php-pgsql-4.3.2-54.ent")) flag++;

if (rpm_check(release:"EL4", reference:"php-4.3.9-3.29")) flag++;
if (rpm_check(release:"EL4", reference:"php-devel-4.3.9-3.29")) flag++;
if (rpm_check(release:"EL4", reference:"php-domxml-4.3.9-3.29")) flag++;
if (rpm_check(release:"EL4", reference:"php-gd-4.3.9-3.29")) flag++;
if (rpm_check(release:"EL4", reference:"php-imap-4.3.9-3.29")) flag++;
if (rpm_check(release:"EL4", reference:"php-ldap-4.3.9-3.29")) flag++;
if (rpm_check(release:"EL4", reference:"php-mbstring-4.3.9-3.29")) flag++;
if (rpm_check(release:"EL4", reference:"php-mysql-4.3.9-3.29")) flag++;
if (rpm_check(release:"EL4", reference:"php-ncurses-4.3.9-3.29")) flag++;
if (rpm_check(release:"EL4", reference:"php-odbc-4.3.9-3.29")) flag++;
if (rpm_check(release:"EL4", reference:"php-pear-4.3.9-3.29")) flag++;
if (rpm_check(release:"EL4", reference:"php-pgsql-4.3.9-3.29")) flag++;
if (rpm_check(release:"EL4", reference:"php-snmp-4.3.9-3.29")) flag++;
if (rpm_check(release:"EL4", reference:"php-xmlrpc-4.3.9-3.29")) flag++;

if (rpm_check(release:"EL5", reference:"php-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"EL5", reference:"php-bcmath-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"EL5", reference:"php-cli-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"EL5", reference:"php-common-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"EL5", reference:"php-dba-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"EL5", reference:"php-devel-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"EL5", reference:"php-gd-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"EL5", reference:"php-imap-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"EL5", reference:"php-ldap-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"EL5", reference:"php-mbstring-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"EL5", reference:"php-mysql-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"EL5", reference:"php-ncurses-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"EL5", reference:"php-odbc-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"EL5", reference:"php-pdo-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"EL5", reference:"php-pgsql-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"EL5", reference:"php-snmp-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"EL5", reference:"php-soap-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"EL5", reference:"php-xml-5.1.6-24.el5_4.5")) flag++;
if (rpm_check(release:"EL5", reference:"php-xmlrpc-5.1.6-24.el5_4.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-bcmath / php-cli / php-common / php-dba / php-devel / etc");
}
