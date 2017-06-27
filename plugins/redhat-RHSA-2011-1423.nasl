#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1423. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56699);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/01/04 16:12:16 $");

  script_cve_id("CVE-2011-0708", "CVE-2011-1148", "CVE-2011-1466", "CVE-2011-1468", "CVE-2011-1469", "CVE-2011-1471", "CVE-2011-1938", "CVE-2011-2202", "CVE-2011-2483");
  script_bugtraq_id(46365, 46843, 46967, 46970, 46975, 46977, 47950, 48259, 49241);
  script_osvdb_id(71597, 72644, 73113, 73218, 73626, 73755, 74742);
  script_xref(name:"RHSA", value:"2011:1423");

  script_name(english:"RHEL 5 / 6 : php53 and php (RHSA-2011:1423)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php53 and php packages that fix several security issues are
now available for Red Hat Enterprise Linux 5 and 6 respectively.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

A signedness issue was found in the way the PHP crypt() function
handled 8-bit characters in passwords when using Blowfish hashing. Up
to three characters immediately preceding a non-ASCII character (one
with the high bit set) had no effect on the hash result, thus
shortening the effective password length. This made brute-force
guessing more efficient as several different passwords were hashed to
the same value. (CVE-2011-2483)

Note: Due to the CVE-2011-2483 fix, after installing this update some
users may not be able to log in to PHP applications that hash
passwords with Blowfish using the PHP crypt() function. Refer to the
upstream 'CRYPT_BLOWFISH security fix details' document, linked to in
the References, for details.

An insufficient input validation flaw, leading to a buffer over-read,
was found in the PHP exif extension. A specially crafted image file
could cause the PHP interpreter to crash when a PHP script tries to
extract Exchangeable image file format (Exif) metadata from the image
file. (CVE-2011-0708)

An integer overflow flaw was found in the PHP calendar extension. A
remote attacker able to make a PHP script call SdnToJulian() with a
large value could cause the PHP interpreter to crash. (CVE-2011-1466)

Multiple memory leak flaws were found in the PHP OpenSSL extension. A
remote attacker able to make a PHP script use openssl_encrypt() or
openssl_decrypt() repeatedly could cause the PHP interpreter to use an
excessive amount of memory. (CVE-2011-1468)

A use-after-free flaw was found in the PHP substr_replace() function.
If a PHP script used the same variable as multiple function arguments,
a remote attacker could possibly use this to crash the PHP interpreter
or, possibly, execute arbitrary code. (CVE-2011-1148)

A bug in the PHP Streams component caused the PHP interpreter to crash
if an FTP wrapper connection was made through an HTTP proxy. A remote
attacker could possibly trigger this issue if a PHP script accepted an
untrusted URL to connect to. (CVE-2011-1469)

An integer signedness issue was found in the PHP zip extension. An
attacker could use a specially crafted ZIP archive to cause the PHP
interpreter to use an excessive amount of CPU time until the script
execution time limit is reached. (CVE-2011-1471)

A stack-based buffer overflow flaw was found in the way the PHP socket
extension handled long AF_UNIX socket addresses. An attacker able to
make a PHP script connect to a long AF_UNIX socket address could use
this flaw to crash the PHP interpreter. (CVE-2011-1938)

An off-by-one flaw was found in PHP. If an attacker uploaded a file
with a specially crafted file name it could cause a PHP script to
attempt to write a file to the root (/) directory. By default, PHP
runs as the 'apache' user, preventing it from writing to the root
directory. (CVE-2011-2202)

All php53 and php users should upgrade to these updated packages,
which contain backported patches to resolve these issues. After
installing the updated packages, the httpd daemon must be restarted
for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-0708.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1148.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1466.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1468.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1469.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1471.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1938.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2202.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2483.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/security/crypt_blowfish.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1423.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-zts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:1423";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-bcmath-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-bcmath-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-bcmath-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-cli-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-cli-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-cli-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-common-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-common-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-common-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-dba-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-dba-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-dba-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-devel-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-devel-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-devel-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-gd-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-gd-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-gd-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-imap-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-imap-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-imap-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-intl-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-intl-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-intl-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-ldap-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-ldap-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-ldap-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-mbstring-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-mbstring-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-mbstring-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-mysql-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-mysql-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-mysql-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-odbc-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-odbc-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-odbc-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-pdo-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-pdo-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-pdo-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-pgsql-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-pgsql-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-pgsql-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-process-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-process-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-process-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-pspell-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-pspell-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-pspell-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-snmp-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-snmp-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-snmp-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-soap-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-soap-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-soap-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-xml-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-xml-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-xml-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-xmlrpc-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-xmlrpc-5.3.3-1.el5_7.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-xmlrpc-5.3.3-1.el5_7.3")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-bcmath-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-bcmath-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-bcmath-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-cli-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-cli-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-cli-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-common-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-common-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-common-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-dba-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-dba-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-dba-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-debuginfo-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-debuginfo-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-debuginfo-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-devel-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-devel-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-devel-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-embedded-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-embedded-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-embedded-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-enchant-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-enchant-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-enchant-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-gd-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-gd-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-gd-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-imap-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-imap-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-imap-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-intl-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-intl-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-intl-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-ldap-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-ldap-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-ldap-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-mbstring-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-mbstring-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-mbstring-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-mysql-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-mysql-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-mysql-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-odbc-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-odbc-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-odbc-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-pdo-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-pdo-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-pdo-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-pgsql-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-pgsql-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-pgsql-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-process-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-process-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-process-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-pspell-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-pspell-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-pspell-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-recode-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-recode-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-recode-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-snmp-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-snmp-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-snmp-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-soap-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-soap-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-soap-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-tidy-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-tidy-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-tidy-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-xml-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-xml-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-xml-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-xmlrpc-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-xmlrpc-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-xmlrpc-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-zts-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-zts-5.3.3-3.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-zts-5.3.3-3.el6_1.3")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-bcmath / php-cli / php-common / php-dba / php-debuginfo / etc");
  }
}
