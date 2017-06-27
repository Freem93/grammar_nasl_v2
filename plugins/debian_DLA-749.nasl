#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-749-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(96010);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2016/12/21 19:25:20 $");

  script_cve_id("CVE-2016-5385", "CVE-2016-7124", "CVE-2016-7128", "CVE-2016-7129", "CVE-2016-7130", "CVE-2016-7131", "CVE-2016-7132", "CVE-2016-7411", "CVE-2016-7412", "CVE-2016-7413", "CVE-2016-7414", "CVE-2016-7416", "CVE-2016-7417", "CVE-2016-7418");
  script_osvdb_id(141667, 143096, 143103, 143104, 143106, 143110, 143111, 144259, 144260, 144261, 144262, 144263, 144268, 144269);

  script_name(english:"Debian DLA-749-1 : php5 security update (httpoxy)");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2016-5385 PHP through 7.0.8 does not attempt to address RFC 3875
section 4.1.18 namespace conflicts and therefore does not protect
applications from the presence of untrusted client data in the
HTTP_PROXY environment variable, which might allow remote attackers to
redirect an application's outbound HTTP traffic to an arbitrary proxy
server via a crafted Proxy header in an HTTP request, as demonstrated
by (1) an application that makes a getenv('HTTP_PROXY') call or (2) a
CGI configuration of PHP, aka an 'httpoxy' issue.

CVE-2016-7124 ext/standard/var_unserializer.c in PHP before 5.6.25 and
7.x before 7.0.10 mishandles certain invalid objects, which allows
remote attackers to cause a denial of service or possibly have
unspecified other impact via crafted serialized data that leads to a
(1) __destruct call or (2) magic method call.

CVE-2016-7128 The exif_process_IFD_in_TIFF function in ext/exif/exif.c
in PHP before 5.6.25 and 7.x before 7.0.10 mishandles the case of a
thumbnail offset that exceeds the file size, which allows remote
attackers to obtain sensitive information from process memory via a
crafted TIFF image.

CVE-2016-7129 The php_wddx_process_data function in ext/wddx/wddx.c in
PHP before 5.6.25 and 7.x before 7.0.10 allows remote attackers to
cause a denial of service (segmentation fault) or possibly have
unspecified other impact via an invalid ISO 8601 time value, as
demonstrated by a wddx_deserialize call that mishandles a dateTime
element in a wddxPacket XML document.

CVE-2016-7130 The php_wddx_pop_element function in ext/wddx/wddx.c in
PHP before 5.6.25 and 7.x before 7.0.10 allows remote attackers to
cause a denial of service (NULL pointer dereference and application
crash) or possibly have unspecified other impact via an invalid base64
binary value, as demonstrated by a wddx_deserialize call that
mishandles a binary element in a wddxPacket XML document.

CVE-2016-7131 ext/wddx/wddx.c in PHP before 5.6.25 and 7.x before
7.0.10 allows remote attackers to cause a denial of service (NULL pointer dereference and application crash) or possibly have
unspecified other impact via a malformed wddxPacket XML document that
is mishandled in a wddx_deserialize call, as demonstrated by a tag
that lacks a < (less than) character.

CVE-2016-7132 ext/wddx/wddx.c in PHP before 5.6.25 and 7.x before
7.0.10 allows remote attackers to cause a denial of service (NULL pointer dereference and application crash) or possibly have
unspecified other impact via an invalid wddxPacket XML document that
is mishandled in a wddx_deserialize call, as demonstrated by a stray
element inside a boolean element, leading to incorrect pop processing.

CVE-2016-7411 ext/standard/var_unserializer.re in PHP before 5.6.26
mishandles object-deserialization failures, which allows remote
attackers to cause a denial of service (memory corruption) or possibly
have unspecified other impact via an unserialize call that references
a partially constructed object.

CVE-2016-7412 ext/mysqlnd/mysqlnd_wireprotocol.c in PHP before 5.6.26
and 7.x before 7.0.11 does not verify that a BIT field has the
UNSIGNED_FLAG flag, which allows remote MySQL servers to cause a
denial of service (heap-based buffer overflow) or possibly have
unspecified other impact via crafted field metadata.

CVE-2016-7413 Use-after-free vulnerability in the wddx_stack_destroy
function in ext/wddx/wddx.c in PHP before 5.6.26 and 7.x before 7.0.11
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via a wddxPacket XML document that lacks an
end-tag for a recordset field element, leading to mishandling in a
wddx_deserialize call.

CVE-2016-7414 The ZIP signature-verification feature in PHP before
5.6.26 and 7.x before 7.0.11 does not ensure that the
uncompressed_filesize field is large enough, which allows remote
attackers to cause a denial of service (out-of-bounds memory access)
or possibly have unspecified other impact via a crafted PHAR archive,
related to ext/phar/util.c and ext/phar/zip.c.

CVE-2016-7416 ext/intl/msgformat/msgformat_format.c in PHP before
5.6.26 and 7.x before 7.0.11 does not properly restrict the locale
length provided to the Locale class in the ICU library, which allows
remote attackers to cause a denial of service (application crash) or
possibly have unspecified other impact via a
MessageFormatter::formatMessage call with a long first argument.

CVE-2016-7417 ext/spl/spl_array.c in PHP before 5.6.26 and 7.x before
7.0.11 proceeds with SplArray unserialization without validating a
return value and data type, which allows remote attackers to cause a
denial of service or possibly have unspecified other impact via
crafted serialized data.

CVE-2016-7418 The php_wddx_push_element function in ext/wddx/wddx.c in
PHP before 5.6.26 and 7.x before 7.0.11 allows remote attackers to
cause a denial of service (invalid pointer access and out-of-bounds
read) or possibly have unspecified other impact via an incorrect
boolean element in a wddxPacket XML document, leading to mishandling
in a wddx_deserialize call.

For Debian 7 'Wheezy', these problems have been fixed in version
5.4.45-0+deb7u6.

We recommend that you upgrade your php5 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/12/msg00024.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/php5"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/16");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/20");
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
if (deb_check(release:"7.0", prefix:"libapache2-mod-php5", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libapache2-mod-php5filter", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libphp5-embed", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php-pear", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-cgi", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-cli", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-common", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-curl", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-dbg", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-dev", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-enchant", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-fpm", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-gd", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-gmp", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-imap", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-interbase", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-intl", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-ldap", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mcrypt", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mysql", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mysqlnd", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-odbc", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-pgsql", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-pspell", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-recode", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-snmp", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-sqlite", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-sybase", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-tidy", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-xmlrpc", reference:"5.4.45-0+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"php5-xsl", reference:"5.4.45-0+deb7u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
