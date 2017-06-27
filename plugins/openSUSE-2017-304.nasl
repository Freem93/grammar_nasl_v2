#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-304.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97563);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/07 17:25:25 $");

  script_cve_id("CVE-2015-8876", "CVE-2016-10158", "CVE-2016-10159", "CVE-2016-10160", "CVE-2016-10161", "CVE-2016-10162", "CVE-2016-10166", "CVE-2016-10167", "CVE-2016-10168", "CVE-2016-7478", "CVE-2016-7479", "CVE-2016-7480", "CVE-2016-9138", "CVE-2017-5340");

  script_name(english:"openSUSE Security Update : php7 (openSUSE-2017-304)");
  script_summary(english:"Check for the openSUSE-2017-304 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for php7 fixes the following security issues :

  - CVE-2016-7480: The SplObjectStorage unserialize
    implementation in ext/spl/spl_observer.c in PHP did not
    verify that a key is an object, which allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (uninitialized memory access) via crafted
    serialized data. (bsc#1019568)

  - CVE-2017-5340: Zend/zend_hash.c in PHP mishandled
    certain cases that require large array allocations,
    which allowed remote attackers to execute arbitrary code
    or cause a denial of service (integer overflow,
    uninitialized memory access, and use of arbitrary
    destructor function pointers) via crafted serialized
    data. (bsc#1019570)

  - CVE-2016-7479: In all versions of PHP 7, during the
    unserialization process, resizing the 'properties' hash
    table of a serialized object may have lead to
    use-after-free. A remote attacker may exploit this bug
    to gain arbitrary code execution. (bsc#1019547)

  - CVE-2016-7478: Zend/zend_exceptions.c in PHP allowed
    remote attackers to cause a denial of service (infinite
    loop) via a crafted Exception object in serialized data,
    a related issue to CVE-2015-8876. (bsc#1019550)

  - CVE-2016-10159: Integer overflow in the
    phar_parse_pharfile function in ext/phar/phar.c in PHP
    allowed remote attackers to cause a denial of service
    (memory consumption or application crash) via a
    truncated manifest entry in a PHAR archive.
    (bsc#1022255)

  - CVE-2016-10160: Off-by-one error in the
    phar_parse_pharfile function in ext/phar/phar.c in PHP
    allowed remote attackers to cause a denial of service
    (memory corruption) or possibly execute arbitrary code
    via a crafted PHAR archive with an alias mismatch.
    (bsc#1022257)

  - CVE-2016-10161: The object_common1 function in
    ext/standard/var_unserializer.c in PHP allowed remote
    attackers to cause a denial of service (buffer over-read
    and application crash) via crafted serialized data that
    is mishandled in a finish_nested_data call.
    (bsc#1022260)

  - CVE-2016-10162: The php_wddx_pop_element function in
    ext/wddx/wddx.c in PHP 7 allowed remote attackers to
    cause a denial of service (NULL pointer dereference and
    application crash) via an inapplicable class name in a
    wddxPacket XML document, leading to mishandling in a
    wddx_deserialize call. (bsc#1022262)

  - CVE-2016-10166: A potential unsigned underflow in gd
    interpolation functions could lead to memory corruption
    in the PHP gd module (bsc#1022263)

  - CVE-2016-10167: A denial of service problem in
    gdImageCreateFromGd2Ctx() could lead to php out of
    memory even on small files. (bsc#1022264)

  - CVE-2016-10168: A signed integer overflow in the gd
    module could lead to memory corruption (bsc#1022265)

  - CVE-2016-9138: PHP mishandled property modification
    during __wakeup processing, which allows remote
    attackers to cause a denial of service or possibly have
    unspecified other impact via crafted serialized data, as
    demonstrated by Exception::__toString with
    DateInterval::__wakeup. (bsc#1008026)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1008026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019568"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022262"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022264"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022265"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php7 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_php7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_php7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-bcmath-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-bz2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-calendar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-ctype-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-dba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-dom-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-enchant-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-exif-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-fastcgi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-fileinfo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-firebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-firebird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-fpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-ftp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-gd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-gettext-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-gmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-iconv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-imap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-intl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-json-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-mbstring-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-mcrypt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-odbc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-opcache-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-pcntl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-pdo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-pear-Archive_Tar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-phar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-phar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-posix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-posix-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-pspell-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-readline-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-shmop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-soap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sockets-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sysvmsg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sysvsem-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sysvshm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-tidy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-tokenizer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-wddx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-xmlreader-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-xmlrpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-xmlwriter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-xsl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-zip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-zlib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"apache2-mod_php7-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"apache2-mod_php7-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-bcmath-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-bcmath-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-bz2-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-bz2-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-calendar-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-calendar-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-ctype-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-ctype-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-curl-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-curl-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-dba-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-dba-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-debugsource-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-devel-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-dom-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-dom-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-enchant-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-enchant-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-exif-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-exif-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-fastcgi-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-fastcgi-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-fileinfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-fileinfo-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-firebird-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-firebird-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-fpm-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-fpm-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-ftp-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-ftp-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-gd-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-gd-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-gettext-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-gettext-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-gmp-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-gmp-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-iconv-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-iconv-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-imap-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-imap-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-intl-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-intl-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-json-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-json-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-ldap-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-ldap-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-mbstring-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-mbstring-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-mcrypt-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-mcrypt-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-mysql-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-mysql-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-odbc-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-odbc-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-opcache-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-opcache-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-openssl-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-openssl-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-pcntl-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-pcntl-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-pdo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-pdo-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-pear-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-pear-Archive_Tar-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-pgsql-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-pgsql-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-phar-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-phar-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-posix-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-posix-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-pspell-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-pspell-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-readline-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-readline-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-shmop-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-shmop-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-snmp-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-snmp-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-soap-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-soap-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-sockets-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-sockets-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-sqlite-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-sqlite-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-sysvmsg-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-sysvmsg-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-sysvsem-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-sysvsem-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-sysvshm-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-sysvshm-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-tidy-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-tidy-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-tokenizer-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-tokenizer-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-wddx-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-wddx-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-xmlreader-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-xmlreader-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-xmlrpc-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-xmlrpc-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-xmlwriter-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-xmlwriter-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-xsl-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-xsl-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-zip-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-zip-debuginfo-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-zlib-7.0.7-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"php7-zlib-debuginfo-7.0.7-12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2-mod_php7 / apache2-mod_php7-debuginfo / php7 / php7-bcmath / etc");
}
