#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-0985.
#

include("compat.inc");

if (description)
{
  script_id(64441);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/19 21:02:56 $");

  script_bugtraq_id(57574);
  script_xref(name:"FEDORA", value:"2013-0985");

  script_name(english:"Fedora 17 : php-symfony2-Yaml-2.1.7-1.fc17 (2013-0985)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated to upstream version 2.1.7

CVE-2013-1397: Ability to enable/disable object support in YAML
parsing and dumping

See:
http://symfony.com/blog/security-release-symfony-2-0-22-and-2-1-7-rele
ased

Changelog:
https://github.com/symfony/symfony/blob/v2.1.7/CHANGELOG-2.1.md

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://symfony.com/blog/security-release-symfony-2-0-22-and-2-1-7-released
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f39d57f5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/symfony/symfony/blob/v2.1.7/CHANGELOG-2.1.md"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-February/098197.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?594ee5ea"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-symfony2-Yaml package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony2-Yaml");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:17");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/04");
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
if (! ereg(pattern:"^17([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 17.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC17", reference:"php-symfony2-Yaml-2.1.7-1.fc17")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-symfony2-Yaml");
}
