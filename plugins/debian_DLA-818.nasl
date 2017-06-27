#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-818-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(97052);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/02/27 16:20:33 $");

  script_cve_id("CVE-2016-10158", "CVE-2016-10159", "CVE-2016-10160", "CVE-2016-10161", "CVE-2016-2554", "CVE-2016-3141", "CVE-2016-3142", "CVE-2016-4342", "CVE-2016-9934", "CVE-2016-9935");
  script_osvdb_id(134031, 134034, 135224, 135225, 147407, 148281, 149623, 149629, 149665, 149666);

  script_name(english:"Debian DLA-818-1 : php5 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several issues have been discovered in PHP (recursive acronym for PHP:
Hypertext Preprocessor), a widely-used open source general-purpose
scripting language that is especially suited for web development and
can be embedded into HTML.

  - CVE-2016-2554 Stack-based buffer overflow in
    ext/phar/tar.c allows remote attackers to cause a denial
    of service (application crash) or possibly have
    unspecified other impact via a crafted TAR archive.

  - CVE-2016-3141 Use-after-free vulnerability in wddx.c in
    the WDDX extension allows remote attackers to cause a
    denial of service (memory corruption and application
    crash) or possibly have unspecified other impact by
    triggering a wddx_deserialize call on XML data
    containing a crafted var element.

  - CVE-2016-3142 The phar_parse_zipfile function in zip.c
    in the PHAR extension in PHP before 5.5.33 and 5.6.x
    before 5.6.19 allows remote attackers to obtain
    sensitive information from process memory or cause a
    denial of service (out-of-bounds read and application
    crash) by placing a PK\x05\x06 signature at an invalid
    location.

  - CVE-2016-4342 ext/phar/phar_object.c in PHP before
    5.5.32, 5.6.x before 5.6.18, and 7.x before 7.0.3
    mishandles zero-length uncompressed data, which allows
    remote attackers to cause a denial of service (heap
    memory corruption) or possibly have unspecified other
    impact via a crafted (1) TAR, (2) ZIP, or (3) PHAR
    archive.

  - CVE-2016-9934 ext/wddx/wddx.c in PHP before 5.6.28 and
    7.x before 7.0.13 allows remote attackers to cause a
    denial of service (NULL pointer dereference) via crafted
    serialized data in a wddxPacket XML document, as
    demonstrated by a PDORow string.

  - CVE-2016-9935 The php_wddx_push_element function in
    ext/wddx/wddx.c in PHP before 5.6.29 and 7.x before
    7.0.14 allows remote attackers to cause a denial of
    service (out-of-bounds read and memory corruption) or
    possibly have unspecified other impact via an empty
    boolean element in a wddxPacket XML document.

  - CVE-2016-10158 The exif_convert_any_to_int function in
    ext/exif/exif.c in PHP before 5.6.30, 7.0.x before
    7.0.15, and 7.1.x before 7.1.1 allows remote attackers
    to cause a denial of service (application crash) via
    crafted EXIF data that triggers an attempt to divide the
    minimum representable negative integer by -1.

  - CVE-2016-10159 Integer overflow in the
    phar_parse_pharfile function in ext/phar/phar.c in PHP
    before 5.6.30 and 7.0.x before 7.0.15 allows remote
    attackers to cause a denial of service (memory
    consumption or application crash) via a truncated
    manifest entry in a PHAR archive.

  - CVE-2016-10160 Off-by-one error in the
    phar_parse_pharfile function in ext/phar/phar.c in PHP
    before 5.6.30 and 7.0.x before 7.0.15 allows remote
    attackers to cause a denial of service (memory
    corruption) or possibly execute arbitrary code via a
    crafted PHAR archive with an alias mismatch.

  - CVE-2016-10161 The object_common1 function in
    ext/standard/var_unserializer.c in PHP before 5.6.30,
    7.0.x before 7.0.15, and 7.1.x before 7.1.1 allows
    remote attackers to cause a denial of service (buffer
    over-read and application crash) via crafted serialized
    data that is mishandled in a finish_nested_data call.

  - BUG-71323.patch Output of stream_get_meta_data can be
    falsified by its input

  - BUG-70979.patch Crash on bad SOAP request

  - BUG-71039.patch exec functions ignore length but look
    for NULL termination

  - BUG-71459.patch Integer overflow in iptcembed()

  - BUG-71391.patch NULL pointer Dereference in
    phar_tar_setupmetadata()

  - BUG-71335.patch Type confusion vulnerability in WDDX
    packet deserialization

For Debian 7 'Wheezy', these problems have been fixed in version
5.4.45-0+deb7u7.

We recommend that you upgrade your php5 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/02/msg00006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/php5"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libapache2-mod-php5", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libapache2-mod-php5filter", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libphp5-embed", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php-pear", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-cgi", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-cli", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-common", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-curl", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-dbg", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-dev", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-enchant", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-fpm", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-gd", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-gmp", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-imap", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-interbase", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-intl", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-ldap", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mcrypt", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mysql", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mysqlnd", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-odbc", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-pgsql", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-pspell", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-recode", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-snmp", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-sqlite", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-sybase", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-tidy", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-xmlrpc", reference:"5.4.45-0+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"php5-xsl", reference:"5.4.45-0+deb7u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
