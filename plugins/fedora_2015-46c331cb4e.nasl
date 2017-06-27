#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-46c331cb4e.
#

include("compat.inc");

if (description)
{
  script_id(89232);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/03/04 16:00:57 $");

  script_xref(name:"FEDORA", value:"2015-46c331cb4e");

  script_name(english:"Fedora 23 : php-horde-horde-5.2.8-1.fc23 / php-horde-imp-6.2.11-1.fc23 / php-horde-ingo-3.2.7-1.fc23 / etc (2015-46c331cb4e)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**horde 5.2.8** * [mjr] SECURITY: Protect against CSRF attacks on
various admin pages. * [jan] Don't apply access keys to checkbox and
radiobox rows in the sidebar (Bug #14103). * [jan] Send correct MIME
type for non-statically cached JavaScript files. * [mjr] Added
configuration support for version 2 of WorldWeatherOnline&apos;s API.
**ingo 3.2.7** * [jan] Update Italian translation. * [mjr] Add
database migration for fixing corrupt rule ordering. * [mjr] Fix
corruption of rule order when reordering rules in certain cases. **imp
6.2.11** * [mjr] Request that the contacts API only consider email
fields when detecting duplicates during automatic saving of attendees
to the address book (Bug #14119). * [jan] Don't show 'Create Keys'
button if creating PGP keys is disabled (steffen.hau at
rz.uni-mannheim.de, Request #14096). * [mjr] Fix displaying iTips with
certain locale/date_format preference combinations (Bug #14076).
**passwd 5.0.4** * [mjr] Fix changing password using Kolab driver
(Mike Gabriel).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-November/170689.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c1d96485"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-November/170690.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?53a20d35"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-November/170691.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aaaee6f1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-November/170692.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?86be3196"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-horde-horde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-horde-imp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-horde-ingo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-horde-passwd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:23");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^23([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 23.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC23", reference:"php-horde-horde-5.2.8-1.fc23")) flag++;
if (rpm_check(release:"FC23", reference:"php-horde-imp-6.2.11-1.fc23")) flag++;
if (rpm_check(release:"FC23", reference:"php-horde-ingo-3.2.7-1.fc23")) flag++;
if (rpm_check(release:"FC23", reference:"php-horde-passwd-5.0.4-1.fc23")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-horde-horde / php-horde-imp / php-horde-ingo / php-horde-passwd");
}
