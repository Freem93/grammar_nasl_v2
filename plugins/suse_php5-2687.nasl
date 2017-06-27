#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update php5-2687.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27390);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/06/13 20:36:48 $");

  script_cve_id("CVE-2006-6383", "CVE-2007-0906", "CVE-2007-0907", "CVE-2007-0908", "CVE-2007-0909", "CVE-2007-0910", "CVE-2007-0911");

  script_name(english:"openSUSE 10 Security Update : php5 (php5-2687)");
  script_summary(english:"Check for the php5-2687 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2007-0906: Multiple buffer overflows in PHP before 5.2.1 allow
attackers to cause a denial of service and possibly execute arbitrary
code via unspecified vectors in the (1) session, (2) zip, (3) imap,
and (4) sqlite extensions; (5) stream filters; and the (6)
str_replace, (7) mail, (8) ibase_delete_user, (9) ibase_add_user, and
(10) ibase_modify_user functions.

CVE-2007-0907: Buffer underflow in PHP before 5.2.1 allows attackers
to cause a denial of service via unspecified vectors involving the
sapi_header_op function.

CVE-2007-0908: The wddx extension in PHP before 5.2.1 allows remote
attackers to obtain sensitive information via unspecified vectors.

CVE-2007-0909: Multiple format string vulnerabilities in PHP before
5.2.1 might allow attackers to execute arbitrary code via format
string specifiers to (1) all of the *print functions on 64-bit
systems, and (2) the odbc_result_all function.

CVE-2007-0910: Unspecified vulnerability in PHP before 5.2.1 allows
attackers to 'clobber' certain super-global variables via unspecified
vectors.

CVE-2007-0911: Off-by-one error in the str_ireplace function in PHP
5.2.1 might allow context-dependent attackers to cause a denial of
service (crash).

CVE-2006-6383: PHP 5.2.0 and 4.4 allows local users to bypass
safe_mode and open_basedir restrictions via a malicious path and a
null byte before a ';' in a session_save_path argument, followed by an
allowed path, which causes a parsing inconsistency in which PHP
validates the allowed path but sets session.save_path to the malicious
path. And another fix for open_basedir was added to stop mixing up its
setting in a virtual host environment."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mhash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mysqli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-zip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE10\.1|SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"apache2-mod_php5-5.1.2-29.25.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-5.1.2-29.25.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-bcmath-5.1.2-29.25.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-curl-5.1.2-29.25.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-dba-5.1.2-29.25.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-devel-5.1.2-29.25.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-dom-5.1.2-29.25.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-exif-5.1.2-29.25.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-fastcgi-5.1.2-29.25.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-ftp-5.1.2-29.25.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-gd-5.1.2-29.25.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-iconv-5.1.2-29.25.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-imap-5.1.2-29.25.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-ldap-5.1.2-29.25.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-mbstring-5.1.2-29.25.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-mhash-5.1.2-29.25.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-mysql-5.1.2-29.25.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-mysqli-5.1.2-29.25.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-odbc-5.1.2-29.25.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-pear-5.1.2-29.25.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-pgsql-5.1.2-29.25.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-soap-5.1.2-29.25.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-sysvmsg-5.1.2-29.25.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-sysvshm-5.1.2-29.25.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-wddx-5.1.2-29.25.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-xmlrpc-5.1.2-29.25.3") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"apache2-mod_php5-5.2.0-12") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-5.2.0-12") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-bcmath-5.2.0-12") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-curl-5.2.0-12") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-dba-5.2.0-12") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-devel-5.2.0-12") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-dom-5.2.0-12") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-exif-5.2.0-12") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-fastcgi-5.2.0-12") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-ftp-5.2.0-12") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-gd-5.2.0-12") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-iconv-5.2.0-12") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-imap-5.2.0-12") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-ldap-5.2.0-12") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-mbstring-5.2.0-12") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-mhash-5.2.0-12") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-mysql-5.2.0-12") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-odbc-5.2.0-12") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-pear-5.2.0-12") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-pgsql-5.2.0-12") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-soap-5.2.0-12") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-sysvmsg-5.2.0-12") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-sysvshm-5.2.0-12") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-wddx-5.2.0-12") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-xmlrpc-5.2.0-12") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-zip-5.2.0-12") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2-mod_php5 / php5 / php5-bcmath / php5-curl / php5-dba / etc");
}
