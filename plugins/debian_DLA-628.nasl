#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-628-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(93568);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/06 20:03:52 $");

  script_cve_id("CVE-2016-4473", "CVE-2016-4538", "CVE-2016-5114", "CVE-2016-5399", "CVE-2016-5768", "CVE-2016-5769", "CVE-2016-5770", "CVE-2016-5771", "CVE-2016-5772", "CVE-2016-5773", "CVE-2016-6289", "CVE-2016-6290", "CVE-2016-6291", "CVE-2016-6292", "CVE-2016-6294", "CVE-2016-6295", "CVE-2016-6296", "CVE-2016-6297");
  script_osvdb_id(132662, 137782, 140377, 140381, 140383, 140384, 140387, 140389, 140391, 141942, 141943, 141944, 141945, 141946, 141954, 141957, 141958, 142018);

  script_name(english:"Debian DLA-628-1 : php5 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - CVE-2016-4473.patch An invalid free may occur under
    certain conditions when processing phar-compatible
    archives.

  - CVE-2016-4538.patch The bcpowmod function in
    ext/bcmath/bcmath.c in PHP before 5.5.35, 5.6.x before
    5.6.21, and 7.x before 7.0.6 accepts a negative integer
    for the scale argument, which allows remote attackers to
    cause a denial of service or possibly have unspecified
    other impact via a crafted call. (already fixed with
    patch for CVE-2016-4537)

  - CVE-2016-5114.patch sapi/fpm/fpm/fpm_log.c in PHP before
    5.5.31, 5.6.x before 5.6.17, and 7.x before 7.0.2
    misinterprets the semantics of the snprintf return
    value, which allows attackers to obtain sensitive
    information from process memory or cause a denial of
    service (out-of-bounds read and buffer overflow) via a
    long string, as demonstrated by a long URI in a
    configuration with custom REQUEST_URI logging.

  - CVE-2016-5399.patch Improper error handling in bzread()

  - CVE-2016-5768.patch Double free vulnerability in the
    _php_mb_regex_ereg_replace_exec function in
    php_mbregex.c in the mbstring extension in PHP before
    5.5.37, 5.6.x before 5.6.23, and 7.x before 7.0.8 allows
    remote attackers to execute arbitrary code or cause a
    denial of service (application crash) by leveraging a
    callback exception.

  - CVE-2016-5769.patch Multiple integer overflows in
    mcrypt.c in the mcrypt extension in PHP before 5.5.37,
    5.6.x before 5.6.23, and 7.x before 7.0.8 allow remote
    attackers to cause a denial of service (heap-based
    buffer overflow and application crash) or possibly have
    unspecified other impact via a crafted length value,
    related to the (1) mcrypt_generic and (2)
    mdecrypt_generic functions.

  - CVE-2016-5770.patch Integer overflow in the
    SplFileObject::fread function in spl_directory.c in the
    SPL extension in PHP before 5.5.37 and 5.6.x before
    5.6.23 allows remote attackers to cause a denial of
    service or possibly have unspecified other impact via a
    large integer argument, a related issue to
    CVE-2016-5096.

  - CVE-2016-5771.patch spl_array.c in the SPL extension in
    PHP before 5.5.37 and 5.6.x before 5.6.23 improperly
    interacts with the unserialize implementation and
    garbage collection, which allows remote attackers to
    execute arbitrary code or cause a denial of service
    (use-after-free and application crash) via crafted
    serialized data.

  - CVE-2016-5772.patch Double free vulnerability in the
    php_wddx_process_data function in wddx.c in the WDDX
    extension in PHP before 5.5.37, 5.6.x before 5.6.23, and
    7.x before 7.0.8 allows remote attackers to cause a
    denial of service (application crash) or possibly
    execute arbitrary code via crafted XML data that is
    mishandled in a wddx_deserialize call.

  - CVE-2016-5773.patch php_zip.c in the zip extension in
    PHP before 5.5.37, 5.6.x before 5.6.23, and 7.x before
    7.0.8 improperly interacts with the unserialize
    implementation and garbage collection, which allows
    remote attackers to execute arbitrary code or cause a
    denial of service (use-after-free and application crash)
    via crafted serialized data containing a ZipArchive
    object.

  - CVE-2016-6289.patch Integer overflow in the
    virtual_file_ex function in TSRM/tsrm_virtual_cwd.c in
    PHP before 5.5.38, 5.6.x before 5.6.24, and 7.x before
    7.0.9 allows remote attackers to cause a denial of
    service (stack-based buffer overflow) or possibly have
    unspecified other impact via a crafted extract operation
    on a ZIP archive.

  - CVE-2016-6290.patch ext/session/session.c in PHP before
    5.5.38, 5.6.x before 5.6.24, and 7.x before 7.0.9 does
    not properly maintain a certain hash data structure,
    which allows remote attackers to cause a denial of
    service (use-after-free) or possibly have unspecified
    other impact via vectors related to session
    deserialization.

  - CVE-2016-6291.patch The exif_process_IFD_in_MAKERNOTE
    function in ext/exif/exif.c in PHP before 5.5.38, 5.6.x
    before 5.6.24, and 7.x before 7.0.9 allows remote
    attackers to cause a denial of service (out-of-bounds
    array access and memory corruption), obtain sensitive
    information from process memory, or possibly have
    unspecified other impact via a crafted JPEG image.

  - CVE-2016-6292.patch The exif_process_user_comment
    function in ext/exif/exif.c in PHP before 5.5.38, 5.6.x
    before 5.6.24, and 7.x before 7.0.9 allows remote
    attackers to cause a denial of service (NULL pointer
    dereference and application crash) via a crafted JPEG
    image.

  - CVE-2016-6294.patch The locale_accept_from_http function
    in ext/intl/locale/locale_methods.c in PHP before
    5.5.38, 5.6.x before 5.6.24, and 7.x before 7.0.9 does
    not properly restrict calls to the ICU
    uloc_acceptLanguageFromHTTP function, which allows
    remote attackers to cause a denial of service
    (out-of-bounds read) or possibly have unspecified other
    impact via a call with a long argument.

  - CVE-2016-6295.patch ext/snmp/snmp.c in PHP before
    5.5.38, 5.6.x before 5.6.24, and 7.x before 7.0.9
    improperly interacts with the unserialize implementation
    and garbage collection, which allows remote attackers to
    cause a denial of service (use-after-free and
    application crash) or possibly have unspecified other
    impact via crafted serialized data, a related issue to
    CVE-2016-5773.

  - CVE-2016-6296.patch Integer signedness error in the
    simplestring_addn function in simplestring.c in
    xmlrpc-epi through 0.54.2, as used in PHP before 5.5.38,
    5.6.x before 5.6.24, and 7.x before 7.0.9, allows remote
    attackers to cause a denial of service (heap-based
    buffer overflow) or possibly have unspecified other
    impact via a long first argument to the PHP
    xmlrpc_encode_request function.

  - CVE-2016-6297.patch Integer overflow in the
    php_stream_zip_opener function in ext/zip/zip_stream.c
    in PHP before 5.5.38, 5.6.x before 5.6.24, and 7.x
    before 7.0.9 allows remote attackers to cause a denial
    of service (stack-based buffer overflow) or possibly
    have unspecified other impact via a crafted zip:// URL.

  - BUG-70436.patch Use After Free Vulnerability in
    unserialize()

  - BUG-72681.patch PHP Session Data Injection
    Vulnerability, consume data even if we're not storing
    them.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/09/msg00021.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/php5"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/19");
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
if (deb_check(release:"7.0", prefix:"libapache2-mod-php5", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libapache2-mod-php5filter", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libphp5-embed", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php-pear", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-cgi", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-cli", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-common", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-curl", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-dbg", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-dev", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-enchant", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-fpm", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-gd", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-gmp", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-imap", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-interbase", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-intl", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-ldap", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mcrypt", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mysql", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-mysqlnd", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-odbc", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-pgsql", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-pspell", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-recode", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-snmp", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-sqlite", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-sybase", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-tidy", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-xmlrpc", reference:"5.4.45-0+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"php5-xsl", reference:"5.4.45-0+deb7u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
