#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-464.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(76722);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/31 01:51:50 $");

  script_cve_id("CVE-2014-0207", "CVE-2014-3478", "CVE-2014-3479", "CVE-2014-3480", "CVE-2014-3487", "CVE-2014-3515");

  script_name(english:"openSUSE Security Update : php / php5 / php53 (openSUSE-SU-2014:0925-1)");
  script_summary(english:"Check for the openSUSE-2014-464 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following security issues with php, php5 and
php53 :

  - bnc#884986, CVE-2014-0207: file: php5:
    cdf_read_short_sector insufficient boundary check 

  - bnc#884987, CVE-2014-3478: file: mconvert incorrect
    handling of truncated pascal string size 

  - bnc#884989, CVE-2014-3479: php53: file:
    cdf_check_stream_offset insufficient boundary check 

  - bnc#884990, CVE-2014-3480: php53: file: cdf_count_chain
    insufficient boundary check 

  - bnc#884991, CVE-2014-3487: php53: file:
    cdf_read_property_info insufficient boundary check 

  - bnc#884992, CVE-2014-3515: php5: unserialize() SPL
    ArrayObject / SPLObjectStorage Type Confusion"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-07/msg00026.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=884986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=884987"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=884989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=884990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=884991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=884992"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php / php5 / php53 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_php5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-bcmath-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-bz2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-calendar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ctype-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-dba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-dom-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-enchant-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-exif-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-fastcgi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-fileinfo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-firebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-firebird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-fpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ftp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gettext-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-iconv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-imap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-intl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-json-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mbstring-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mcrypt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mssql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mssql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-odbc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pcntl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pdo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-phar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-phar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-posix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-posix-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pspell-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-readline-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-shmop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-soap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sockets-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-suhosin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-suhosin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sysvmsg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sysvsem-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sysvshm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-tidy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-tokenizer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-wddx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xmlreader-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xmlrpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xmlwriter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xsl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-zip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-zlib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/24");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"apache2-mod_php5-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-mod_php5-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-bcmath-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-bcmath-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-bz2-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-bz2-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-calendar-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-calendar-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-ctype-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-ctype-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-curl-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-curl-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-dba-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-dba-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-debugsource-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-devel-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-dom-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-dom-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-enchant-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-enchant-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-exif-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-exif-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-fastcgi-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-fastcgi-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-fileinfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-fileinfo-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-fpm-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-fpm-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-ftp-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-ftp-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-gd-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-gd-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-gettext-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-gettext-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-gmp-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-gmp-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-iconv-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-iconv-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-imap-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-imap-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-intl-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-intl-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-json-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-json-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-ldap-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-ldap-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-mbstring-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-mbstring-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-mcrypt-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-mcrypt-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-mssql-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-mssql-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-mysql-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-mysql-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-odbc-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-odbc-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-openssl-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-openssl-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-pcntl-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-pcntl-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-pdo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-pdo-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-pear-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-pgsql-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-pgsql-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-phar-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-phar-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-posix-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-posix-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-pspell-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-pspell-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-readline-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-readline-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-shmop-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-shmop-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-snmp-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-snmp-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-soap-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-soap-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-sockets-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-sockets-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-sqlite-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-sqlite-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-suhosin-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-suhosin-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-sysvmsg-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-sysvmsg-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-sysvsem-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-sysvsem-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-sysvshm-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-sysvshm-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-tidy-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-tidy-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-tokenizer-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-tokenizer-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-wddx-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-wddx-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-xmlreader-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-xmlreader-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-xmlrpc-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-xmlrpc-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-xmlwriter-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-xmlwriter-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-xsl-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-xsl-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-zip-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-zip-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-zlib-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"php5-zlib-debuginfo-5.3.17-3.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-mod_php5-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-mod_php5-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-bcmath-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-bcmath-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-bz2-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-bz2-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-calendar-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-calendar-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-ctype-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-ctype-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-curl-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-curl-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-dba-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-dba-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-debugsource-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-devel-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-dom-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-dom-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-enchant-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-enchant-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-exif-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-exif-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-fastcgi-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-fastcgi-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-fileinfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-fileinfo-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-firebird-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-firebird-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-fpm-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-fpm-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-ftp-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-ftp-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-gd-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-gd-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-gettext-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-gettext-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-gmp-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-gmp-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-iconv-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-iconv-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-imap-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-imap-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-intl-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-intl-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-json-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-json-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-ldap-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-ldap-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-mbstring-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-mbstring-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-mcrypt-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-mcrypt-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-mssql-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-mssql-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-mysql-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-mysql-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-odbc-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-odbc-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-openssl-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-openssl-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-pcntl-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-pcntl-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-pdo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-pdo-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-pear-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-pgsql-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-pgsql-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-phar-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-phar-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-posix-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-posix-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-pspell-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-pspell-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-readline-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-readline-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-shmop-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-shmop-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-snmp-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-snmp-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-soap-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-soap-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-sockets-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-sockets-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-sqlite-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-sqlite-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-suhosin-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-suhosin-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-sysvmsg-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-sysvmsg-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-sysvsem-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-sysvsem-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-sysvshm-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-sysvshm-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-tidy-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-tidy-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-tokenizer-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-tokenizer-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-wddx-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-wddx-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-xmlreader-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-xmlreader-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-xmlrpc-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-xmlrpc-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-xmlwriter-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-xmlwriter-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-xsl-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-xsl-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-zip-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-zip-debuginfo-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-zlib-5.4.20-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-zlib-debuginfo-5.4.20-16.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php5 / php53");
}
