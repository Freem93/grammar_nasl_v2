#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-703.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91585);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/10/13 14:37:12 $");

  script_cve_id("CVE-2013-7456", "CVE-2015-4116", "CVE-2015-8873", "CVE-2015-8874", "CVE-2015-8876", "CVE-2015-8877", "CVE-2015-8879", "CVE-2016-3074", "CVE-2016-5093", "CVE-2016-5094", "CVE-2016-5095", "CVE-2016-5096", "CVE-2016-5114");

  script_name(english:"openSUSE Security Update : php5 (openSUSE-2016-703)");
  script_summary(english:"Check for the openSUSE-2016-703 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for php5 fixes the following issues :

  - CVE-2013-7456: imagescale out-of-bounds read
    (bnc#982009).

  - CVE-2016-5093: get_icu_value_internal out-of-bounds read
    (bnc#982010).

  - CVE-2016-5094: Don't create strings with lengths outside
    int range (bnc#982011).

  - CVE-2016-5095: Don't create strings with lengths outside
    int range (bnc#982012).

  - CVE-2016-5096: int/size_t confusion in fread
    (bsc#982013).

  - CVE-2016-5114: fpm_log.c memory leak and buffer overflow
    (bnc#982162).

  - CVE-2015-8877: The gdImageScaleTwoPass function in
    gd_interpolation.c in the GD Graphics Library (aka
    libgd), as used in PHP, used inconsistent allocate and
    free approaches, which allowed remote attackers to cause
    a denial of service (memory consumption) via a crafted
    call, as demonstrated by a call to the PHP imagescale
    function (bsc#981061).

  - CVE-2015-8876: Zend/zend_exceptions.c in PHP did not
    validate certain Exception objects, which allowed remote
    attackers to cause a denial of service (NULL pointer
    dereference and application crash) or trigger unintended
    method execution via crafted serialized data
    (bsc#981049).

  - CVE-2015-8879: The odbc_bindcols function in
    ext/odbc/php_odbc.c in PHP mishandled driver behavior
    for SQL_WVARCHAR columns, which allowed remote attackers
    to cause a denial of service (application crash) in
    opportunistic circumstances by leveraging use of the
    odbc_fetch_array function to access a certain type of
    Microsoft SQL Server table Aliased: (bsc#981050).

  - CVE-2015-4116: Use-after-free vulnerability in the
    spl_ptr_heap_insert function in ext/spl/spl_heap.c in
    PHP allowed remote attackers to execute arbitrary code
    by triggering a failed SplMinHeap::compare operation
    (bsc#980366).

  - CVE-2015-8874: Stack consumption vulnerability in GD in
    PHP allowed remote attackers to cause a denial of
    service via a crafted imagefilltoborder call
    (bsc#980375).

  - CVE-2015-8873: Stack consumption vulnerability in
    Zend/zend_exceptions.c in PHP allowed remote attackers
    to cause a denial of service (segmentation fault) via
    recursive method calls (bsc#980373).

  - CVE-2016-3074: Integer signedness error in GD Graphics
    Library (aka libgd or libgd2) allowed remote attackers
    to cause a denial of service (crash) or potentially
    execute arbitrary code via crafted compressed gd2 data,
    which triggers a heap-based buffer overflow
    (bsc#976775)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=976775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980366"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982162"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-opcache-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"apache2-mod_php5-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-mod_php5-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-bcmath-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-bcmath-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-bz2-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-bz2-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-calendar-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-calendar-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-ctype-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-ctype-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-curl-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-curl-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-dba-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-dba-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-debugsource-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-devel-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-dom-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-dom-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-enchant-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-enchant-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-exif-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-exif-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-fastcgi-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-fastcgi-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-fileinfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-fileinfo-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-firebird-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-firebird-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-fpm-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-fpm-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-ftp-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-ftp-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-gd-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-gd-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-gettext-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-gettext-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-gmp-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-gmp-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-iconv-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-iconv-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-imap-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-imap-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-intl-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-intl-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-json-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-json-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-ldap-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-ldap-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-mbstring-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-mbstring-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-mcrypt-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-mcrypt-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-mssql-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-mssql-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-mysql-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-mysql-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-odbc-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-odbc-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-opcache-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-opcache-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-openssl-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-openssl-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pcntl-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pcntl-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pdo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pdo-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pear-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pgsql-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pgsql-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-phar-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-phar-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-posix-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-posix-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pspell-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pspell-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-readline-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-readline-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-shmop-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-shmop-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-snmp-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-snmp-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-soap-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-soap-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sockets-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sockets-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sqlite-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sqlite-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-suhosin-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-suhosin-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sysvmsg-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sysvmsg-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sysvsem-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sysvsem-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sysvshm-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sysvshm-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-tidy-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-tidy-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-tokenizer-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-tokenizer-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-wddx-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-wddx-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-xmlreader-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-xmlreader-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-xmlrpc-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-xmlrpc-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-xmlwriter-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-xmlwriter-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-xsl-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-xsl-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-zip-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-zip-debuginfo-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-zlib-5.6.1-66.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-zlib-debuginfo-5.6.1-66.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2-mod_php5 / apache2-mod_php5-debuginfo / php5 / php5-bcmath / etc");
}
