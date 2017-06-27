#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-21069.
#

include("compat.inc");

if (description)
{
  script_id(63400);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/20 22:44:20 $");

  script_xref(name:"FEDORA", value:"2012-21069");

  script_name(english:"Fedora 16 : php-symfony2-HttpKernel-2.0.21-1.fc16 (2012-21069)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated to upstream version 2.0.21.

See :

  -
    http://symfony.com/blog/security-release-symfony-2-0-20-
    and-2-1-5-released

    -
      http://symfony.com/blog/symfony-2-0-21-and-2-1-5-relea
      sed

Changelogs :

  - 2.0.20 > 2.0.21:
    https://github.com/symfony/symfony/compare/v2.0.20...v2.
    0.21

    - 2.0.19 > 2.0.20:
      https://github.com/symfony/symfony/compare/v2.0.19...v
      2.0.20

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://symfony.com/blog/security-release-symfony-2-0-20-and-2-1-5-released
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e9cf4bd9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://symfony.com/blog/symfony-2-0-21-and-2-1-5-released"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/symfony/symfony/compare/v2.0.19...v2.0.20"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/symfony/symfony/compare/v2.0.20...v2.0.21"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-January/095435.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68b34b3c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-symfony2-HttpKernel package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony2-HttpKernel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:16");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/08");
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
if (! ereg(pattern:"^16([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 16.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC16", reference:"php-symfony2-HttpKernel-2.0.21-1.fc16")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-symfony2-HttpKernel");
}
