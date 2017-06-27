#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update apache2-mod_php5-4810.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(29878);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/22 20:32:45 $");

  script_cve_id("CVE-2005-4872", "CVE-2006-7227", "CVE-2006-7228", "CVE-2006-7230", "CVE-2007-1659", "CVE-2007-1660", "CVE-2007-3996", "CVE-2007-3998", "CVE-2007-4658", "CVE-2007-4661", "CVE-2007-4782", "CVE-2007-4784", "CVE-2007-4825", "CVE-2007-4840", "CVE-2007-5898");

  script_name(english:"openSUSE 10 Security Update : apache2-mod_php5 (apache2-mod_php5-4810)");
  script_summary(english:"Check for the apache2-mod_php5-4810 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes multiple bugs in php :

  - use system pcre library to fix several pcre
    vulnerabilities (CVE-2007-1659, CVE-2006-7230,
    CVE-2007-1660, CVE-2006-7227 CVE-2005-4872,
    CVE-2006-7228)

  - Flaws in processing multi byte sequences in
    htmlentities/htmlspecialchars (CVE-2007-5898)

  - overly long arguments to the dl() function could crash
    php (CVE-2007-4825)

  - overy long arguments to the glob() function could crash
    php (CVE-2007-4782)

  - overly long arguments to some iconv functions could
    crash php (CVE-2007-4840)

  - overy long arguments to the setlocale() function could
    crash php (CVE-2007-4784)

  - the wordwrap-Function could cause a floating point
    exception (CVE-2007-3998)

  - overy long arguments to the fnmatch() function could
    crash php (CVE-2007-4782)

  - incorrect size calculation in the chunk_split function
    could lead to a buffer overflow (CVE-2007-4661)

  - Flaws in the GD extension could lead to integer
    overflows (CVE-2007-3996)

  - The money_format function contained format string flaws
    (CVE-2007-4658)

  - Data for some time zones has been updated"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2-mod_php5 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(20, 22, 94, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-dbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-filepro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mhash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mysqli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pdo_mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pdo_pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pdo_sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-posix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-zlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"apache2-mod_php5-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-bcmath-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-bz2-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-calendar-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-ctype-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-curl-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-dba-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-dbase-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-devel-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-dom-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-exif-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-fastcgi-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-filepro-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-ftp-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-gd-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-gettext-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-gmp-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-iconv-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-imap-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-ldap-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-mbstring-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-mcrypt-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-mhash-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-mysql-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-mysqli-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-ncurses-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-odbc-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-openssl-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-pcntl-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-pdo-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-pdo_mysql-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-pdo_pgsql-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-pdo_sqlite-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-pear-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-pgsql-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-posix-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-pspell-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-shmop-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-snmp-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-soap-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-sockets-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-sqlite-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-sysvmsg-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-sysvsem-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-sysvshm-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-tidy-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-tokenizer-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-wddx-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-xmlreader-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-xmlrpc-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-xmlwriter-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-xsl-5.1.2-29.50") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-zlib-5.1.2-29.50") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2-mod_php5 / php5 / php5-bcmath / php5-bz2 / php5-calendar / etc");
}
