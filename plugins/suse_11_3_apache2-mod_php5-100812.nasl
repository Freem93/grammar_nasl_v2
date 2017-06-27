#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update apache2-mod_php5-2929.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75429);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2010-0397", "CVE-2010-1860", "CVE-2010-1862", "CVE-2010-1864", "CVE-2010-1866", "CVE-2010-1914", "CVE-2010-1915", "CVE-2010-1917", "CVE-2010-2093", "CVE-2010-2094", "CVE-2010-2097", "CVE-2010-2100", "CVE-2010-2101", "CVE-2010-2190", "CVE-2010-2191", "CVE-2010-2225", "CVE-2010-2531", "CVE-2010-2950", "CVE-2010-3062", "CVE-2010-3063", "CVE-2010-3064", "CVE-2010-3065");

  script_name(english:"openSUSE Security Update : apache2-mod_php5 (openSUSE-SU-2010:0599-1)");
  script_summary(english:"Check for the apache2-mod_php5-2929 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"PHP was updated to version 5.3.3 to fix serveral security issues.

(CVE-2010-0397, CVE-2010-1860, CVE-2010-1862, CVE-2010-1864,
CVE-2010-1866, CVE-2010-1914, CVE-2010-1915, CVE-2010-1917,
CVE-2010-2093, CVE-2010-2094, CVE-2010-2097, CVE-2010-2100,
CVE-2010-2101, CVE-2010-2190, CVE-2010-2191, CVE-2010-2225,
CVE-2010-2531, CVE-2010-2950, CVE-2010-3062, CVE-2010-3063,
CVE-2010-3064, CVE-2010-3065)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-09/msg00013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=588975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=604315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=604652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=604654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=604656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=605097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=605100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=609763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=609766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=609768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=609769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=612555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=612556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=616232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=619483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=619486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=619487"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=619489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=633932"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=633934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=636923"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2-mod_php5 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-hash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-phar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-posix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-suhosin");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-zlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"apache2-mod_php5-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-bcmath-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-bz2-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-calendar-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-ctype-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-curl-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-dba-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-devel-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-dom-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-enchant-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-exif-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-fastcgi-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-fileinfo-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-ftp-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-gd-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-gettext-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-gmp-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-hash-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-iconv-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-imap-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-intl-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-json-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-ldap-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-mbstring-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-mcrypt-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-mysql-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-odbc-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-openssl-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-pcntl-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-pdo-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-pear-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-pgsql-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-phar-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-posix-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-pspell-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-readline-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-shmop-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-snmp-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-soap-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-sockets-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-sqlite-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-suhosin-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-sysvmsg-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-sysvsem-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-sysvshm-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-tidy-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-tokenizer-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-wddx-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-xmlreader-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-xmlrpc-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-xmlwriter-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-xsl-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-zip-5.3.3-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"php5-zlib-5.3.3-0.1.2") ) flag++;

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
