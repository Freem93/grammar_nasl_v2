#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-23164.
#

include("compat.inc");

if (description)
{
  script_id(71549);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/19 21:47:14 $");

  script_cve_id("CVE-2013-6420");
  script_xref(name:"FEDORA", value:"2013-23164");

  script_name(english:"Fedora 20 : php-5.5.7-1.fc20 (2013-23164)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"12 Dec 2013, PHP 5.5.7

CLI server :

  - Added some MIME types to the CLI web server (Chris
    Jones)

    - Implemented FR #65917 (getallheaders() is not
      supported by the built-in web server) - also
      implements apache_response_headers() (Andrea Faulds)

Core :

  - Fixed bug #66094 (unregister_tick_function tries to cast
    a Closure to a string). (Laruence)

OPCache

  - Fixed bug #66176 (Invalid constant substitution).
    (Dmitry)

    - Fixed bug #65915 (Inconsistent results with require
      return value). (Dmitry)

    - Fixed bug #65559 (Opcache: cache not cleared if
      changes occur while running). (Dmitry)

OpenSSL :

  - Fixed memory corruption in openssl_x509_parse()
    (CVE-2013-6420). (Stefan Esser).

readline

  - Fixed Bug #65714 (PHP cli forces the tty to cooked
    mode). (Remi)

Backported from 5.5.8 :

  - fix zend_register_functions breaks reflection, php bug
    66218

    - fix Heap buffer over-read in DateInterval, php bug
      66060

    - fix fix overflow handling bug in non-x86

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1036830"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/124718.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5756969b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/20");
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
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"php-5.5.7-1.fc20")) flag++;


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
