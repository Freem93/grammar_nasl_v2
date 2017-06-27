#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-499-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(91397);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/12/06 20:03:51 $");

  script_cve_id("CVE-2015-8865", "CVE-2015-8866", "CVE-2015-8878", "CVE-2015-8879", "CVE-2016-4070", "CVE-2016-4071", "CVE-2016-4072", "CVE-2016-4073", "CVE-2016-4343", "CVE-2016-4537", "CVE-2016-4539", "CVE-2016-4540", "CVE-2016-4541", "CVE-2016-4542", "CVE-2016-4543", "CVE-2016-4544");
  script_osvdb_id(122863, 125858, 134037, 136483, 136484, 136485, 136486, 137753, 137781, 137782, 137783, 137784, 138955);

  script_name(english:"Debian DLA-499-1 : php5 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - CVE-2015-8865 The file_check_mem function in funcs.c in
    file before 5.23, as used in the Fileinfo component in
    PHP before 5.5.34, 5.6.x before 5.6.20, and 7.x before
    7.0.5, mishandles continuation-level jumps, which allows
    context-dependent attackers to cause a denial of service
    (buffer overflow and application crash) or possibly
    execute arbitrary code via a crafted magic file.

  - CVE-2015-8866 libxml_disable_entity_loader setting is
    shared between threads ext/libxml/libxml.c in PHP before
    5.5.22 and 5.6.x before 5.6.6, when PHP-FPM is used,
    does not isolate each thread from
    libxml_disable_entity_loader changes in other threads,
    which allows remote attackers to conduct XML External
    Entity (XXE) and XML Entity Expansion (XEE) attacks via
    a crafted XML document, a related issue to
    CVE-2015-5161.

  - CVE-2015-8878 main/php_open_temporary_file.c in PHP
    before 5.5.28 and 5.6.x before 5.6.12 does not ensure
    thread safety, which allows remote attackers to cause a
    denial of service (race condition and heap memory
    corruption) by leveraging an application that performs
    many temporary-file accesses.

  - CVE-2015-8879 The odbc_bindcols function in
    ext/odbc/php_odbc.c in PHP before 5.6.12 mishandles
    driver behavior for SQL_WVARCHAR columns, which allows
    remote attackers to cause a denial of service
    (application crash) in opportunistic circumstances by
    leveraging use of the odbc_fetch_array function to
    access a certain type of Microsoft SQL Server table.

  - CVE-2016-4070 Integer overflow in the php_raw_url_encode
    function in ext/standard/url.c in PHP before 5.5.34,
    5.6.x before 5.6.20, and 7.x before 7.0.5 allows remote
    attackers to cause a denial of service (application
    crash) via a long string to the rawurlencode function.

  - CVE-2016-4071 Format string vulnerability in the
    php_snmp_error function in ext/snmp/snmp.c in PHP before
    5.5.34, 5.6.x before 5.6.20, and 7.x before 7.0.5 allows
    remote attackers to execute arbitrary code via format
    string specifiers in an SNMP::get call.

  - CVE-2016-4072 The Phar extension in PHP before 5.5.34,
    5.6.x before 5.6.20, and 7.x before 7.0.5 allows remote
    attackers to execute arbitrary code via a crafted
    filename, as demonstrated by mishandling of \0
    characters by the phar_analyze_path function in
    ext/phar/phar.c.

  - CVE-2016-4073 Multiple integer overflows in the
    mbfl_strcut function in
    ext/mbstring/libmbfl/mbfl/mbfilter.c in PHP before
    5.5.34, 5.6.x before 5.6.20, and 7.x before 7.0.5 allow
    remote attackers to cause a denial of service
    (application crash) or possibly execute arbitrary code
    via a crafted mb_strcut call.

  - CVE-2016-4343 The phar_make_dirstream function in
    ext/phar/dirstream.c in PHP before 5.6.18 and 7.x before
    7.0.3 mishandles zero-size ././@LongLink files, which
    allows remote attackers to cause a denial of service
    (uninitialized pointer dereference) or possibly have
    unspecified other impact via a crafted TAR archive.

  - CVE-2016-4537 The bcpowmod function in
    ext/bcmath/bcmath.c in PHP before 5.5.35, 5.6.x before
    5.6.21, and 7.x before 7.0.6 accepts a negative integer
    for the scale argument, which allows remote attackers to
    cause a denial of service or possibly have unspecified
    other impact via a crafted call.

  - CVE-2016-4539 The xml_parse_into_struct function in
    ext/xml/xml.c in PHP before 5.5.35, 5.6.x before 5.6.21,
    and 7.x before 7.0.6 allows remote attackers to cause a
    denial of service (buffer under-read and segmentation
    fault) or possibly have unspecified other impact via
    crafted XML data in the second argument, leading to a
    parser level of zero.

  - CVE-2016-4540

  - CVE-2016-4541 The grapheme_strpos function in
    ext/intl/grapheme/grapheme_string.c in before 5.5.35,
    5.6.x before 5.6.21, and 7.x before 7.0.6 allows remote
    attackers to cause a denial of service (out-of-bounds
    read) or possibly have unspecified other impact via a
    negative offset.

  - CVE-2016-4542

  - CVE-2016-4543

  - CVE-2016-4544 The exif_process_* function in
    ext/exif/exif.c in PHP before 5.5.35, 5.6.x before
    5.6.21, and 7.x before 7.0.6 does not validate IFD
    sizes, which allows remote attackers to cause a denial
    of service (out-of-bounds read) or possibly have
    unspecified other impact via crafted header data.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/05/msg00053.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/php5"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-php5filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libphp5-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-interbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-xsl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"7.0", prefix:"libapache2-mod-php5", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libapache2-mod-php5filter", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libphp5-embed", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php-pear", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-cgi", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-cli", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-common", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-curl", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-dbg", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-dev", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-enchant", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-fpm", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-gd", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-gmp", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-imap", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-interbase", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-intl", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-ldap", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mcrypt", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mysql", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mysqlnd", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-odbc", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-pgsql", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-pspell", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-recode", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-snmp", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-sqlite", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-sybase", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-tidy", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-xmlrpc", reference:"5.4.45-0+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"php5-xsl", reference:"5.4.45-0+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
