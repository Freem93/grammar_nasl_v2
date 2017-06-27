#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-341-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86794);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/12/06 20:03:51 $");

  script_cve_id("CVE-2015-6831", "CVE-2015-6832", "CVE-2015-6833", "CVE-2015-6834", "CVE-2015-6836", "CVE-2015-6837", "CVE-2015-6838", "CVE-2015-7803", "CVE-2015-7804");
  script_osvdb_id(125849, 125850, 125851, 125854, 125856, 126951, 126952, 126953, 126954, 126989, 128347, 128348);

  script_name(english:"Debian DLA-341-1 : php5 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - CVE-2015-6831 Use after free vulnerability was found in
    unserialize() function. We can create ZVAL and free it
    via Serializable::unserialize. However the unserialize()
    will still allow to use R: or r: to set references to
    that already freed memory. It is possible to
    use-after-free attack and execute arbitrary code
    remotely.

  - CVE-2015-6832 Dangling pointer in the unserialization of
    ArrayObject items.

  - CVE-2015-6833 Files extracted from archive may be placed
    outside of destination directory

  - CVE-2015-6834 Use after free vulnerability was found in
    unserialize() function. We can create ZVAL and free it
    via Serializable::unserialize. However the unserialize()
    will still allow to use R: or r: to set references to
    that already freed memory. It is possible to
    use-after-free attack and execute arbitrary code
    remotely.

  - CVE-2015-6836 A type confusion occurs within SOAP
    serialize_function_call due to an insufficient
    validation of the headers field. In the SoapClient's
    __call method, the verify_soap_headers_array check is
    applied only to headers retrieved from
    zend_parse_parameters; problem is that a few lines
    later, soap_headers could be updated or even replaced
    with values from the __default_headers object fields.

  - CVE-2015-6837 The XSLTProcessor class misses a few
    checks on the input from the libxslt library. The
    valuePop() function call is able to return NULL pointer
    and php does not check that.

  - CVE-2015-6838 The XSLTProcessor class misses a few
    checks on the input from the libxslt library. The
    valuePop() function call is able to return NULL pointer
    and php does not check that.

  - CVE-2015-7803 A NULL pointer dereference flaw was found
    in the way PHP's Phar extension parsed Phar archives. A
    specially crafted archive could cause PHP to crash.

  - CVE-2015-7804 An uninitialized pointer use flaw was
    found in the phar_make_dirstream() function of PHP's
    Phar extension. A specially crafted phar file in the ZIP
    format with a directory entry with a file name '/ZIP'
    could cause a PHP application function to crash.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/11/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/php5"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/09");
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
if (deb_check(release:"6.0", prefix:"libapache2-mod-php5", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"libapache2-mod-php5filter", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php-pear", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php5", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php5-cgi", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php5-cli", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php5-common", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php5-curl", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php5-dbg", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php5-dev", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php5-enchant", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php5-gd", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php5-gmp", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php5-imap", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php5-interbase", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php5-intl", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php5-ldap", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php5-mcrypt", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php5-mysql", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php5-odbc", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php5-pgsql", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php5-pspell", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php5-recode", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php5-snmp", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php5-sqlite", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php5-sybase", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php5-tidy", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php5-xmlrpc", reference:"5.3.3.1-7+squeeze28")) flag++;
if (deb_check(release:"6.0", prefix:"php5-xsl", reference:"5.3.3.1-7+squeeze28")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
