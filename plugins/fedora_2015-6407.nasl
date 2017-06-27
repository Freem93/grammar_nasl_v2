#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-6407.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(83044);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2015/10/19 23:14:52 $");

  script_cve_id("CVE-2015-1351", "CVE-2015-1352", "CVE-2015-2783");
  script_xref(name:"FEDORA", value:"2015-6407");

  script_name(english:"Fedora 21 : php-5.6.8-1.fc21 (2015-6407)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"16 Apr 2015, **PHP 5.6.8**

Core :

  - Fixed bug #66609 (php crashes with __get() and ++
    operator in some cases). (Dmitry, Laruence)

    - Fixed bug #68021 (get_browser() browser_name_regex
      returns non-utf-8 characters). (Tjerk)

    - Fixed bug #68917 (parse_url fails on some partial
      urls). (Wei Dai)

    - Fixed bug #69134 (Per Directory Values overrides
      PHP_INI_SYSTEM configuration options). (Anatol Belski)

    - Additional fix for bug #69152 (Type confusion
      vulnerability in exception::getTraceAsString). (Stas)

    - Fixed bug #69210 (serialize function return corrupted
      data when sleep has non-string values). (Juan Basso)

    - Fixed bug #69212 (Leaking VIA_HANDLER func when
      exception thrown in __call/... arg passing). (Nikita)

    - Fixed bug #69221 (Segmentation fault when using a
      generator in combination with an Iterator). (Nikita)

    - Fixed bug #69337 (php_stream_url_wrap_http_ex()
      type-confusion vulnerability). (Stas)

    - Fixed bug #69353 (Missing null byte checks for paths
      in various PHP extensions). (Stas)

Apache2handler :

  - Fixed bug #69218 (potential remote code execution with
    apache 2.4 apache2handler). (Gerrit Venema)

cURL :

  - Implemented FR#69278 (HTTP2 support). (Masaki Kagaya)

    - Fixed bug #68739 (Missing break / control flow).
      (Laruence)

    - Fixed bug #69316 (Use-after-free in php_curl related
      to CURLOPT_FILE/_INFILE/_WRITEHEADER). (Laruence)

Date :

  - Fixed bug #69336 (Issues with 'last day of
    <monthname>'). (Derick Rethans)

Enchant :

  - Fixed bug #65406 (Enchant broker plugins are in the
    wrong place in windows builds). (Anatol)

Ereg :

  - Fixed bug #68740 (NULL pointer Dereference). (Laruence)

Fileinfo :

  - Fixed bug #68819 (Fileinfo on specific file causes
    spurious OOM and/or segfault). (Anatol Belski)

Filter :

  - Fixed bug #69202: (FILTER_FLAG_STRIP_BACKTICK ignored
    unless other flags are used). (Jeff Welch)

    - Fixed bug #69203 (FILTER_FLAG_STRIP_HIGH doesn't strip
      ASCII 127). (Jeff Welch)

OPCache :

  - Fixed bug #69297 (function_exists strange behavior with
    OPCache on disabled function). (Laruence)

    - Fixed bug #69281 (opcache_is_script_cached no longer
      works). (danack)

    - Fixed bug #68677 (Use After Free). (CVE-2015-1351)
      (Laruence)

OpenSSL

  - Fixed bugs #68853, #65137 (Buffered crypto stream data
    breaks IO polling in stream_select() contexts) (Chris
    Wright)

    - Fixed bug #69197 (openssl_pkcs7_sign handles default
      value incorrectly) (Daniel Lowrey)

    - Fixed bug #69215 (Crypto servers should send client CA
      list) (Daniel Lowrey)

    - Add a check for RAND_egd to allow compiling against
      LibreSSL (Leigh)

Phar :

  - Fixed bug #64343 (PharData::extractTo fails for tarball
    created by BSD tar). (Mike)

    - Fixed bug #64931 (phar_add_file is too restrictive on
      filename). (Mike)

    - Fixed bug #65467 (Call to undefined method
      cli_arg_typ_string). (Mike)

    - Fixed bug #67761 (Phar::mapPhar fails for Phars inside
      a path containing '.tar'). (Mike)

    - Fixed bug #69324 (Buffer Over-read in unserialize when
      parsing Phar). (Stas)

    - Fixed bug #69441 (Buffer Overflow when parsing
      tar/zip/phar in phar_set_inode). (Stas)

Postgres :

  - Fixed bug #68741 (NULL pointer dereference).
    (CVE-2015-1352) (Laruence)

SPL :

  - Fixed bug #69227 (Use after free in zval_scan caused by
    spl_object_storage_get_gc). (adam dot scarr at 99designs
    dot com)

SOAP :

  - Fixed bug #69293 (NEW segfault when using
    SoapClient::__setSoapHeader (bisected, regression)).
    (Laruence)

Sqlite3 :

  - Fixed bug #68760 (SQLITE segfaults if custom collator
    throws an exception). (Dan Ackroyd)

    - Fixed bug #69287 (Upgrade bundled libsqlite to
      3.8.8.3). (Anatol)

    - Fixed bug #66550 (SQLite prepared statement
      use-after-free). (Sean Heelan)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1185900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1185904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1213407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1213411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1213416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1213442"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1213446"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-April/155932.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7e19a0be"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^21([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 21.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC21", reference:"php-5.6.8-1.fc21")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}
