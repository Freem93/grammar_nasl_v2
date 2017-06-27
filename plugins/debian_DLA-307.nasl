#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-307-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(85808);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/06 20:03:51 $");

  script_cve_id("CVE-2015-3307", "CVE-2015-3411", "CVE-2015-3412", "CVE-2015-4021", "CVE-2015-4022", "CVE-2015-4025", "CVE-2015-4026", "CVE-2015-4147", "CVE-2015-4148", "CVE-2015-4598", "CVE-2015-4599", "CVE-2015-4600", "CVE-2015-4601", "CVE-2015-4602", "CVE-2015-4604", "CVE-2015-4605", "CVE-2015-4643", "CVE-2015-4644", "CVE-2015-5589", "CVE-2015-5590");
  script_bugtraq_id(73357, 74413, 74700, 74703, 74902, 74904, 75056, 75103, 75233, 75241, 75244, 75246, 75249, 75250, 75251, 75255, 75291, 75292, 75970, 75974);
  script_osvdb_id(117588, 119772, 120926, 121321, 121398, 122125, 122126, 122257, 122261, 122268, 123148, 123639, 123677, 124239, 124242);

  script_name(english:"Debian DLA-307-1 : php5 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - CVE-2015-3307 The phar_parse_metadata function in
    ext/phar/phar.c in PHP before 5.4.40, 5.5.x before
    5.5.24, and 5.6.x before 5.6.8 allows remote attackers
    to cause a denial of service (heap metadata corruption)
    or possibly have unspecified other impact via a crafted
    tar archive.

  - CVE-2015-3411 + CVE-2015-3412 Fixed bug #69353 (Missing
    null byte checks for paths in various PHP extensions)

  - CVE-2015-4021 The phar_parse_tarfile function in
    ext/phar/tar.c in PHP before 5.4.41, 5.5.x before
    5.5.25, and 5.6.x before 5.6.9 does not verify that the
    first character of a filename is different from the \0
    character, which allows remote attackers to cause a
    denial of service (integer underflow and memory
    corruption) via a crafted entry in a tar archive.

  - CVE-2015-4022 Integer overflow in the ftp_genlist
    function in ext/ftp/ftp.c in PHP before 5.4.41, 5.5.x
    before 5.5.25, and 5.6.x before 5.6.9 allows remote FTP
    servers to execute arbitrary code via a long reply to a
    LIST command, leading to a heap-based buffer overflow.

  - CVE-2015-4025 PHP before 5.4.41, 5.5.x before 5.5.25,
    and 5.6.x before 5.6.9 truncates a pathname upon
    encountering a \x00 character in certain situations,
    which allows remote attackers to bypass intended
    extension restrictions and access files or directories
    with unexpected names via a crafted argument to (1)
    set_include_path, (2) tempnam, (3) rmdir, or (4)
    readlink. NOTE: this vulnerability exists because of an
    incomplete fix for CVE-2006-7243.

  - CVE-2015-4026 The pcntl_exec implementation in PHP
    before 5.4.41, 5.5.x before 5.5.25, and 5.6.x before
    5.6.9 truncates a pathname upon encountering a \x00
    character, which might allow remote attackers to bypass
    intended extension restrictions and execute files with
    unexpected names via a crafted first argument. NOTE:
    this vulnerability exists because of an incomplete fix
    for CVE-2006-7243.

  - CVE-2015-4147 The SoapClient::__call method in
    ext/soap/soap.c in PHP before 5.4.39, 5.5.x before
    5.5.23, and 5.6.x before 5.6.7 does not verify that
    __default_headers is an array, which allows remote
    attackers to execute arbitrary code by providing crafted
    serialized data with an unexpected data type, related to
    a 'type confusion' issue.

  - CVE-2015-4148 The do_soap_call function in
    ext/soap/soap.c in PHP before 5.4.39, 5.5.x before
    5.5.23, and 5.6.x before 5.6.7 does not verify that the
    uri property is a string, which allows remote attackers
    to obtain sensitive information by providing crafted
    serialized data with an int data type, related to a
    'type confusion' issue.

  - CVE-2015-4598 Incorrect handling of paths with NULs

  - CVE-2015-4599 Type confusion vulnerability in
    exception::getTraceAsString

  - CVE-2015-4600 + CVE-2015-4601 Added type checks

  - CVE-2015-4602 Type Confusion Infoleak Vulnerability in
    unserialize() with SoapFault

  - CVE-2015-4604 + CVE-2015-4605 denial of service when
    processing a crafted file with Fileinfo (already fixed
    in CVE-2015-temp-68819.patch)

  - CVE-2015-4643 Improved fix for bug #69545 (Integer
    overflow in ftp_genlist() resulting in heap overflow)

  - CVE-2015-4644 Fixed bug #69667 (segfault in
    php_pgsql_meta_data)

  - CVE-2015-5589 Segfault in Phar::convertToData on invalid
    file

  - CVE-2015-5590 Buffer overflow and stack smashing error
    in phar_fix_filepath

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/09/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/php5"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-php5filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-interbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-mysql");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libapache2-mod-php5", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"libapache2-mod-php5filter", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php-pear", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php5", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php5-cgi", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php5-cli", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php5-common", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php5-curl", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php5-dbg", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php5-dev", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php5-enchant", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php5-gd", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php5-gmp", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php5-imap", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php5-interbase", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php5-intl", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php5-ldap", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php5-mcrypt", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php5-mysql", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php5-odbc", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php5-pgsql", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php5-pspell", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php5-recode", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php5-snmp", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php5-sqlite", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php5-sybase", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php5-tidy", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php5-xmlrpc", reference:"5.3.3.1-7+squeeze27")) flag++;
if (deb_check(release:"6.0", prefix:"php5-xsl", reference:"5.3.3.1-7+squeeze27")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
