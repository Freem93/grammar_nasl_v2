#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-14998.
#

include("compat.inc");

if (description)
{
  script_id(69462);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/19 21:12:42 $");

  script_cve_id("CVE-2011-4718", "CVE-2013-4248");
  script_bugtraq_id(61776, 61929);
  script_xref(name:"FEDORA", value:"2013-14998");

  script_name(english:"Fedora 19 : php-5.5.3-1.fc19 (2013-14998)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Version 5.5.3, 22 Aug 2013

Openssl: + Fixed UMR in fix for CVE-2013-4248.

Version 5.5.2, 15-Aug-2013

Core :

  - Fixed bug #65372 (Segfault in gc_zval_possible_root when
    return reference fails).

    - Fixed value of FILTER_SANITIZE_FULL_SPECIAL_CHARS
      constant (previously was erroneously set to
      FILTER_SANITIZE_SPECIAL_CHARS value).

    - Fixed bug #65304 (Use of max int in array_sum).

    - Fixed bug #65291 (get_defined_constants() causes PHP
      to crash in a very limited case).

    - Fixed bug #62691 (solaris sed has no -i switch).

    - Fixed bug #61345 (CGI mode - make install don't work).

    - Fixed bug #61268 (--enable-dtrace leads make to
      clobber Zend/zend_dtrace.d).

DOM :

  - Added flags option to DOMDocument::schemaValidate() and
    DOMDocument::schemaValidateSource(). Added
    LIBXML_SCHEMA_CREATE flag.

OPcache :

  - Added opcache.restrict_api configuration directive that
    may limit usage of OPcahce API functions only to
    patricular script(s).

    - Added support for glob symbols in blacklist entries
      (?, *, **).

    - Fixed bug #65338 (Enabling both php_opcache and
      php_wincache AVs on shutdown).

Openssl :

  - Fixed handling null bytes in subjectAltName
    (CVE-2013-4248).

PDO_mysql :

  - Fixed bug #65299 (pdo mysql parsing errors).

Phar :

  - Fixed bug #65028 (Phar::buildFromDirectory creates
    corrupt archives for some specific contents).

Pgsql :

  - Fixed bug #62978 (Disallow possible SQL injections with
    pg_select()/pg_update() /pg_delete()/pg_insert()).

    - Fixed bug #65336 (pg_escape_literal/identifier()
      silently returns false).

Sessions :

  - Implemented strict sessions RFC
    (https://wiki.php.net/rfc/strict_sessions) which
    protects against session fixation attacks and session
    collisions (CVE-2011-4718).

    - Fixed possible buffer overflow under Windows. Note:
      Not a security fix.

    - Changed session.auto_start to PHP_INI_PERDIR.

SOAP :

  - Fixed bug #65018 (SoapHeader problems with SoapServer).

SPL :

  - Fixed bug #65328 (Segfault when getting SplStack object
    Value).

    - Added RecursiveTreeIterator setPostfix and getPostifx
      methods.

    - Fixed bug #61697 (spl_autoload_functions returns
      lambda functions incorrectly).

Streams :

  - Fixed bug #65268 (select() implementation uses outdated
    tick API).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=996774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=997097"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-August/114648.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cad3df9a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.php.net/rfc/strict_sessions"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:19");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/25");
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
if (! ereg(pattern:"^19([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 19.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC19", reference:"php-5.5.3-1.fc19")) flag++;


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
