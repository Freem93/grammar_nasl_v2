#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-1101.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(81191);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/19 22:49:05 $");

  script_cve_id("CVE-2014-8142", "CVE-2014-9427", "CVE-2015-0231", "CVE-2015-0232");
  script_xref(name:"FEDORA", value:"2015-1101");

  script_name(english:"Fedora 20 : php-5.5.21-1.fc20 (2015-1101)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"22 Jan 2014, PHP 5.5.21

Core :

  - Upgraded crypt_blowfish to version 1.3. (Leigh)

    - Fixed bug #60704 (unlink() bug with some files path).

    - Fixed bug #65419 (Inside trait, self::class !=
      __CLASS__). (Julien)

    - Fixed bug #65576 (Constructor from trait conflicts
      with inherited constructor). (dunglas at gmail dot
      com)

    - Fixed bug #55541 (errors spawn MessageBox, which
      blocks test automation). (Anatol)

    - Fixed bug #68297 (Application Popup provides too few
      information). (Anatol)

    - Fixed bug #65769 (localeconv() broken in TS builds).
      (Anatol)

    - Fixed bug #65230 (setting locale randomly broken).
      (Anatol)

    - Fixed bug #66764 (configure doesn't define
      EXPANDED_DATADIR / PHP_DATADIR correctly). (Ferenc)

    - Fixed bug #68583 (Crash in timeout thread). (Anatol)

    - Fixed bug #68676 (Explicit Double Free). (Kalle)

    - Fixed bug #68710 (Use After Free Vulnerability in
      PHP's unserialize()). (CVE-2015-0231) (Stefan Esser)

CGI :

  - Fixed bug #68618 (out of bounds read crashes
    php-cgi).(CVE-2014-9427) (Stas)

CLI server :

  - Fixed bug #68745 (Invalid HTTP requests make web server
    segfault). (Adam)

cURL :

  - Fixed bug #67643 (curl_multi_getcontent returns ' when
    CURLOPT_RETURNTRANSFER isn't set). (Jille Timmermans)

EXIF :

  - Fixed bug #68799: Free called on uninitialized pointer.
    (CVE-2015-0232) (Stas)

Fileinfo :

  - Fixed bug #68671 (incorrect expression in libmagic).
    (Joshua Rogers, Anatol Belski)

    - Removed readelf.c and related code from libmagic
      sources (Remi, Anatol)

    - Fixed bug #68735 (fileinfo out-of-bounds memory
      access). (Anatol)

FPM :

  - Fixed bug #68751 (listen.allowed_clients is broken).
    (Remi)

GD :

  - Fixed bug #68601 (buffer read overflow in gd_gif_in.c).
    (Jan Bee, Remi)

Mbstring :

  - Fixed bug #68504 (--with-libmbfl configure option not
    present on Windows). (Ashesh Vashi)

Mcrypt :

  - Fixed possible read after end of buffer and use after
    free. (Dmitry)

Opcache :

  - Fixed bug #67111 (Memory leak when using 'continue 2'
    inside two foreach loops). (Nikita)

OpenSSL :

  - Fixed bug #55618 (use case-insensitive cert name
    matching). (Daniel Lowrey)

Pcntl :

  - Fixed bug #60509 (pcntl_signal doesn't decrease
    ref-count of old handler when setting SIG_DFL). (Julien)

PCRE :

  - Fixed bug #66679 (Alignment Bug in PCRE 8.34 upstream).
    (Rainer Jung, Anatol Belski)

pgsql :

  - Fixed bug #68697 (lo_export return -1 on failure).
    (Ondrej Sury)

PDO :

  - Fixed bug #68371 (PDO#getAttribute() cannot be called
    with platform-specific attribute names). (Matteo)

PDO_mysql :

  - Fixed bug #68424 (Add new PDO mysql connection attr to
    control multi statements option). (peter dot wolanin at
    acquia dot com)

SPL :

  - Fixed bug #66405
    (RecursiveDirectoryIterator::CURRENT_AS_PATHNAME breaks
    the RecursiveIterator). (Paul Garvin)

    - Fixed bug #65213 (cannot cast SplFileInfo to boolean)
      (Tjerk)

    - Fixed bug #68479 (Added escape parameter to
      SplFileObject::fputcsv). (Salathe)

SQLite :

  - Fixed bug #68120 (Update bundled libsqlite to 3.8.7.2).
    (Anatol)

Streams :

  - Fixed bug #68532 (convert.base64-encode omits padding
    bytes). (blaesius at krumedia dot de)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1178736"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1185397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1185472"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-February/149192.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?88137ef8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/06");
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
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"php-5.5.21-1.fc20")) flag++;


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
