#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-14985.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(69815);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/19 21:12:42 $");

  script_cve_id("CVE-2013-4248");
  script_bugtraq_id(61776);
  script_xref(name:"FEDORA", value:"2013-14985");

  script_name(english:"Fedora 18 : php-5.4.19-1.fc18 (2013-14985)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Version 5.4.19, 22-Aug-2013

Core :

  - Fixed bug #64503 (Compilation fails with error:
    conflicting types for 'zendparse'). (Laruence)

Openssl :

  - Fixed UMR in fix for CVE-2013-4248.

Version 5.4.18, 15-Aug-2013

Core :

  - Fixed value of FILTER_SANITIZE_FULL_SPECIAL_CHARS
    constant (previously was erroneously set to
    FILTER_SANITIZE_SPECIAL_CHARS value).

    - Fixed bug #65254 (Exception not catchable when
      exception thrown in autoload with a namespace).

    - Fixed bug #65108 (is_callable() triggers Fatal Error).

    - Fixed bug #65088 (Generated configure script is
      malformed on OpenBSD).

    - Fixed bug #62964 (Possible XSS on 'Registered stream
      filters' info).

    - Fixed bug #62672 (Error on serialize of ArrayObject).

    - Fixed bug #62475 (variant_* functions causes crash
      when null given as an argument).

    - Fixed bug #60732 (php_error_docref links to invalid
      pages).

    - Fixed bug #65226 (chroot() does not get enabled).

CLI server :

  - Fixed bug #65066 (Cli server not responsive when
    responding with 422 http status code).

CURL :

  - Fixed bug #62665 (curl.cainfo doesn't appear in
    php.ini).

FTP :

  - Fixed bug #65228 (FTPs memory leak with SSL).

GMP :

  - Fixed bug #65227 (Memory leak in gmp_cmp second
    parameter).

Imap :

  - Fixed bug #64467 (Segmentation fault after imap_reopen
    failure).

Intl :

  - Fixed bug #62759 (Buggy grapheme_substr() on edge case).
    Fixed bug #61860 (Offsets may be wrong for
    grapheme_stri* functions).

mysqlnd :

  - Fixed segfault in mysqlnd when doing long prepare.

ODBC :

  - Fixed bug #61387 (NULL valued anonymous column causes
    segfault in odbc_fetch_array).

Openssl :

  - Fixed handling null bytes in subjectAltName
    (CVE-2013-4248).

PDO_dblib :

  - Fixed bug #65219 (PDO/dblib not working anymore ('use
    dbName' not sent)).

PDO_pgsql :

  - Fixed meta data retrieve when OID is larger than 2^31.

Session :

  - Fixed bug #62535 ($_SESSION[$key]['cancel_upload']
    doesn't work as documented).

    - Fixed bug #35703 (when session_name('123') consist
      only digits, should warning).

    - Fixed bug #49175 (mod_files.sh does not support hash
      bits).

Sockets :

  - Implemented FR #63472 (Setting SO_BINDTODEVICE with
    socket_set_option).

SPL :

  - Fixed bug #65136 (RecursiveDirectoryIterator segfault).

    - Fixed bug #61828 (Memleak when calling
      Directory(Recursive)Iterator /Spl(Temp)FileObject ctor
      twice).

    - Fixed bug #60560 (SplFixedArray un-/serialize,
      getSize(), count() return 0, keys are strings).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=997097"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-September/115349.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?40464961"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"php-5.4.19-1.fc18")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}
