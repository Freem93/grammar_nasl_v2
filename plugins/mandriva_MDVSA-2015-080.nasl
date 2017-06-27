#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:080. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(82333);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/05 13:44:22 $");

  script_cve_id("CVE-2013-7345", "CVE-2014-0185", "CVE-2014-0207", "CVE-2014-0237", "CVE-2014-0238", "CVE-2014-1943", "CVE-2014-2270", "CVE-2014-3478", "CVE-2014-3479", "CVE-2014-3480", "CVE-2014-3487", "CVE-2014-3515", "CVE-2014-3538", "CVE-2014-3587", "CVE-2014-3597", "CVE-2014-3669", "CVE-2014-3670", "CVE-2014-3710", "CVE-2014-4049", "CVE-2014-4670", "CVE-2014-4698", "CVE-2014-4721", "CVE-2014-8116", "CVE-2014-8117", "CVE-2014-8142", "CVE-2014-9425", "CVE-2014-9427", "CVE-2014-9620", "CVE-2014-9621", "CVE-2014-9705", "CVE-2015-0231", "CVE-2015-0232", "CVE-2015-0273", "CVE-2015-1351", "CVE-2015-1352", "CVE-2015-2301", "CVE-2015-2331");
  script_xref(name:"MDVSA", value:"2015:080");

  script_name(english:"Mandriva Linux Security Advisory : php (MDVSA-2015:080)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities has been discovered and corrected in php :

It was discovered that the file utility contains a flaw in the
handling of indirect magic rules in the libmagic library, which leads
to an infinite recursion when trying to determine the file type of
certain files (CVE-2014-1943).

A flaw was found in the way the file utility determined the type of
Portable Executable (PE) format files, the executable format used on
Windows. A malicious PE file could cause the file utility to crash or,
potentially, execute arbitrary code (CVE-2014-2270).

The BEGIN regular expression in the awk script detector in
magic/Magdir/commands in file before 5.15 uses multiple wildcards with
unlimited repetitions, which allows context-dependent attackers to
cause a denial of service (CPU consumption) via a crafted ASCII file
that triggers a large amount of backtracking, as demonstrated via a
file with many newline characters (CVE-2013-7345).

PHP FPM in PHP versions before 5.4.28 and 5.5.12 uses a UNIX domain
socket with world-writable permissions by default, which allows any
local user to connect to it and execute PHP scripts as the apache user
(CVE-2014-0185).

A flaw was found in the way file's Composite Document Files (CDF)
format parser handle CDF files with many summary info entries. The
cdf_unpack_summary_info() function unnecessarily repeatedly read the
info from the same offset. This led to many file_printf() calls in
cdf_file_property_info(), which caused file to use an excessive amount
of CPU time when parsing a specially crafted CDF file (CVE-2014-0237).

A flaw was found in the way file parsed property information from
Composite Document Files (CDF) files. A property entry with 0 elements
triggers an infinite loop (CVE-2014-0238).

The unserialize() function in PHP before 5.4.30 and 5.5.14 has a Type
Confusion issue related to the SPL ArrayObject and SPLObjectStorage
Types (CVE-2014-3515).

It was discovered that PHP is vulnerable to a heap-based buffer
overflow in the DNS TXT record parsing. A malicious server or
man-in-the-middle attacker could possibly use this flaw to execute
arbitrary code as the PHP interpreter if a PHP application uses
dns_get_record() to perform a DNS query (CVE-2014-4049).

A flaw was found in the way file parsed property information from
Composite Document Files (CDF) files, where the mconvert() function
did not correctly compute the truncated pascal string size
(CVE-2014-3478).

Multiple flaws were found in the way file parsed property information
from Composite Document Files (CDF) files, due to insufficient
boundary checks on buffers (CVE-2014-0207, CVE-2014-3479,
CVE-2014-3480, CVE-2014-3487).

The phpinfo() function in PHP before 5.4.30 and 5.5.14 has a Type
Confusion issue that can cause it to leak arbitrary process memory
(CVE-2014-4721).

Use-after-free vulnerability in ext/spl/spl_array.c in the SPL
component in PHP through 5.5.14 allows context-dependent attackers to
cause a denial of service or possibly have unspecified other impact
via crafted ArrayIterator usage within applications in certain
web-hosting environments (CVE-2014-4698).

Use-after-free vulnerability in ext/spl/spl_dllist.c in the SPL
component in PHP through 5.5.14 allows context-dependent attackers to
cause a denial of service or possibly have unspecified other impact
via crafted iterator usage within applications in certain web-hosting
environments (CVE-2014-4670).

file before 5.19 does not properly restrict the amount of data read
during a regex search, which allows remote attackers to cause a denial
of service (CPU consumption) via a crafted file that triggers
backtracking during processing of an awk rule, due to an incomplete
fix for CVE-2013-7345 (CVE-2014-3538).

Integer overflow in the cdf_read_property_info function in cdf.c in
file through 5.19, as used in the Fileinfo component in PHP before
5.4.32 and 5.5.x before 5.5.16, allows remote attackers to cause a
denial of service (application crash) via a crafted CDF file. NOTE:
this vulnerability exists because of an incomplete fix for
CVE-2012-1571 (CVE-2014-3587).

Multiple buffer overflows in the php_parserr function in
ext/standard/dns.c in PHP before 5.4.32 and 5.5.x before 5.5.16 allow
remote DNS servers to cause a denial of service (application crash) or
possibly execute arbitrary code via a crafted DNS record, related to
the dns_get_record function and the dn_expand function. NOTE: this
issue exists because of an incomplete fix for CVE-2014-4049
(CVE-2014-3597).

An integer overflow flaw in PHP's unserialize() function was reported.
If unserialize() were used on untrusted data, this issue could lead to
a crash or potentially information disclosure (CVE-2014-3669).

A heap corruption issue was reported in PHP's exif_thumbnail()
function. A specially crafted JPEG image could cause the PHP
interpreter to crash or, potentially, execute arbitrary code
(CVE-2014-3670).

If client-supplied input was passed to PHP's cURL client as a URL to
download, it could return local files from the server due to improper
handling of null bytes (PHP#68089).

An out-of-bounds read flaw was found in file's donote() function in
the way the file utility determined the note headers of a elf file.
This could possibly lead to file executable crash (CVE-2014-3710).

A use-after-free flaw was found in PHP unserialize(). An untrusted
input could cause PHP interpreter to crash or, possibly, execute
arbitrary code when processed using unserialize() (CVE-2014-8142).

Double free vulnerability in the zend_ts_hash_graceful_destroy
function in zend_ts_hash.c in the Zend Engine in PHP before 5.5.21
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via unknown vectors (CVE-2014-9425).

sapi/cgi/cgi_main.c in the CGI component in PHP before 5.5.21, when
mmap is used to read a .php file, does not properly consider the
mapping's length during processing of an invalid file that begins with
a # character and lacks a newline character, which causes an
out-of-bounds read and might allow remote attackers to obtain
sensitive information from php-cgi process memory by leveraging the
ability to upload a .php file or trigger unexpected code execution if
a valid PHP script is present in memory locations adjacent to the
mapping (CVE-2014-9427).

Use after free vulnerability in unserialize() in PHP before 5.5.21
(CVE-2015-0231).

Free called on an uninitialized pointer in php-exif in PHP before
5.5.21 (CVE-2015-0232).

The readelf.c source file has been removed from PHP's bundled copy of
file's libmagic, eliminating exposure to denial of service issues in
ELF file parsing such as CVE-2014-8116, CVE-2014-8117, CVE-2014-9620
and CVE-2014-9621 in PHP's fileinfo module.

S. Paraschoudis discovered that PHP incorrectly handled memory in the
enchant binding. A remote attacker could use this issue to cause PHP
to crash, resulting in a denial of service, or possibly execute
arbitrary code (CVE-2014-9705).

Taoguang Chen discovered that PHP incorrectly handled unserializing
objects. A remote attacker could use this issue to cause PHP to crash,
resulting in a denial of service, or possibly execute arbitrary code
(CVE-2015-0273).

It was discovered that PHP incorrectly handled memory in the phar
extension. A remote attacker could use this issue to cause PHP to
crash, resulting in a denial of service, or possibly execute arbitrary
code (CVE-2015-2301).

Use-after-free vulnerability in the process_nested_data function in
ext/standard/var_unserializer.re in PHP before 5.4.37, 5.5.x before
5.5.21, and 5.6.x before 5.6.5 allows remote attackers to execute
arbitrary code via a crafted unserialize call that leverages improper
handling of duplicate numerical keys within the serialized properties
of an object. NOTE: this vulnerability exists because of an incomplete
fix for CVE-2014-8142 (CVE-2015-0231).

The exif_process_unicode function in ext/exif/exif.c in PHP before
5.4.37, 5.5.x before 5.5.21, and 5.6.x before 5.6.5 allows remote
attackers to execute arbitrary code or cause a denial of service
(uninitialized pointer free and application crash) via crafted EXIF
data in a JPEG image (CVE-2015-0232).

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way libzip, which is embedded in PHP, processed certain
ZIP archives. If an attacker were able to supply a specially crafted
ZIP archive to an application using libzip, it could cause the
application to crash or, possibly, execute arbitrary code
(CVE-2015-2331).

It was discovered that the PHP opcache component incorrectly handled
memory. A remote attacker could possibly use this issue to cause PHP
to crash, resulting in a denial of service, or possibly execute
arbitrary code (CVE-2015-1351).

It was discovered that the PHP PostgreSQL database extension
incorrectly handled certain pointers. A remote attacker could possibly
use this issue to cause PHP to crash, resulting in a denial of
service, or possibly execute arbitrary code (CVE-2015-1352).

PHP contains a bundled copy of the file utility's libmagic library, so
it was vulnerable to the libmagic issues.

The updated php packages have been patched and upgraded to the 5.5.23
version which is not vulnerable to these issues. The libzip packages
has been patched to address the CVE-2015-2331 flaw.

A bug in the php zip extension that could cause a crash has been fixed
(mga#13820)

Additionally the jsonc and timezonedb packages has been upgraded to
the latest versions and the PECL packages which requires so has been
rebuilt for php-5.5.23."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0163.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0178.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0215.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0258.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0284.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0324.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0367.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0430.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0441.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0542.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2015-0040.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-5.php#5.5.10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-5.php#5.5.11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-5.php#5.5.12"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-5.php#5.5.13"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-5.php#5.5.14"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-5.php#5.5.15"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-5.php#5.5.16"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-5.php#5.5.17"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-5.php#5.5.18"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-5.php#5.5.19"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-5.php#5.5.20"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-5.php#5.5.21"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-5.php#5.5.22"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-5.php#5.5.23"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-5.php#5.5.9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ubuntu.com/usn/usn-2501-1/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ubuntu.com/usn/usn-2535-1/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.mageia.org/show_bug.cgi?id=13820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1204676"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64php5_common5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64zip-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64zip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libzip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-hash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-interbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-mssql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-mysqli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pdo_dblib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pdo_firebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pdo_mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pdo_odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pdo_pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pdo_sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-phar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-posix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-sockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-sybase_ct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-timezonedb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-zlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"apache-mod_php-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64php5_common5-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64zip-devel-0.11.2-1.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64zip2-0.11.2-1.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"libzip-0.11.2-1.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-bcmath-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-bz2-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-calendar-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-cgi-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-cli-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-ctype-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-curl-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-dba-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-devel-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"php-doc-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-dom-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-enchant-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-exif-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-fileinfo-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-filter-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-fpm-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-ftp-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-gd-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-gettext-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-gmp-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-hash-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-iconv-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-imap-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-ini-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-interbase-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-intl-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-json-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-ldap-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-mbstring-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-mcrypt-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-mssql-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-mysql-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-mysqli-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-mysqlnd-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-odbc-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-opcache-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-openssl-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-pcntl-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-pdo-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-pdo_dblib-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-pdo_firebird-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-pdo_mysql-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-pdo_odbc-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-pdo_pgsql-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-pdo_sqlite-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-pgsql-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-phar-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-posix-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-readline-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-recode-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-session-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-shmop-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-snmp-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-soap-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-sockets-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-sqlite3-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-sybase_ct-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-sysvmsg-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-sysvsem-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-sysvshm-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-tidy-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-timezonedb-2015.1-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-tokenizer-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-wddx-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-xml-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-xmlreader-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-xmlrpc-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-xmlwriter-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-xsl-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-zip-5.5.23-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"php-zlib-5.5.23-1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
