#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-6901.
#

include("compat.inc");

if (description)
{
  script_id(76093);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/19 22:40:32 $");

  script_cve_id("CVE-2014-0237", "CVE-2014-0238");
  script_bugtraq_id(67759, 67765);
  script_xref(name:"FEDORA", value:"2014-6901");

  script_name(english:"Fedora 20 : php-phpunit-PHPUnit-MockObject-1.2.3-4.fc20 / php-5.5.13-3.fc20 / etc (2014-6901)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"29 May 2014, PHP 5.5.13

CLI server :

  - Fixed bug #67079 (Missing MIME types for XML/XSL files).
    (Anatol)

COM :

  - Fixed bug #66431 (Special Character via COM Interface
    (CP_UTF8)). (Anatol)

Core :

  - Fixed bug #65701 (copy() doesn't work when destination
    filename is created by tempnam()). (Boro Sitnikovski)

    - Fixed bug #67072 (Echoing unserialized 'SplFileObject'
      crash). (Anatol)

    - Fixed bug #67245 (usage of memcpy() with overlapping
      src and dst in zend_exceptions.c). (Bob)

    - Fixed bug #67247 (spl_fixedarray_resize integer
      overflow). (Stas)

    - Fixed bug #67249 (printf out-of-bounds read). (Stas)

    - Fixed bug #67250 (iptcparse out-of-bounds read).
      (Stas)

    - Fixed bug #67252 (convert_uudecode out-of-bounds
      read). (Stas)

Curl :

  - Fixed bug #64247 (CURLOPT_INFILE doesn't allow reset).
    (Mike)

Date :

  - Fixed bug #67118 (DateTime constructor crash with
    invalid data). (Anatol)

    - Fixed bug #67251 (date_parse_from_format out-of-bounds
      read). (Stas)

    - Fixed bug #67253 (timelib_meridian_with_check
      out-of-bounds read). (Stas)

DOM :

  - Fixed bug #67081 (DOMDocumentType->internalSubset
    returns entire DOCTYPE tag, not only the subset).
    (Anatol)

Fileinfo :

  - Fixed bug #66307 (Fileinfo crashes with powerpoint
    files). (Anatol)

    - Fixed bug #67327 (fileinfo: CDF infinite loop in
      nelements DoS) (CVE-2014-0238).

    - Fixed bug #67328 (fileinfo: fileinfo: numerous
      file_printf calls resulting in performance
      degradation) (CVE-2014-0237).

FPM :

  - Fixed bug #66908 (php-fpm reload leaks epoll_create()
    file descriptor). (Julio Pintos)

GD :

  - Fixed bug #67248 (imageaffinematrixget missing check of
    parameters). (Stas)

PCRE :

  - Fixed bug #67238 (Ungreedy and min/max quantifier bug,
    applied patch from the upstream). (Anatol)

Phar :

  - Fix bug #64498 ($phar->buildFromDirectory can't compress
    file with an accent in its name). (PR #588)

Backported from 5.5.14 :

  - Fileinfo: Fixed bug #67326 (fileinfo:
    cdf_read_short_sector insufficient boundary check).

    - Core: workaround regression introduce in fix for
      #67072

    - Date: Fixed regression in fix for bug #67118
      (constructor can't be called twice).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1098155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1098193"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-June/134438.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f0aec936"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-June/134439.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fbd0b597"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-June/134440.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c3a9fa79"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected php, php-doctrine-orm and / or
php-phpunit-PHPUnit-MockObject packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-doctrine-orm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-phpunit-PHPUnit-MockObject");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC20", reference:"php-5.5.13-3.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"php-doctrine-orm-2.4.2-2.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"php-phpunit-PHPUnit-MockObject-1.2.3-4.fc20")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-doctrine-orm / php-phpunit-PHPUnit-MockObject");
}
