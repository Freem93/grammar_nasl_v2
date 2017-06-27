#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-6610.
#

include("compat.inc");

if (description)
{
  script_id(58936);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/20 22:53:51 $");

  script_xref(name:"FEDORA", value:"2012-6610");

  script_name(english:"Fedora 15 : firefox-12.0-1.fc15 / gnome-python2-extras-2.25.3-35.fc15.7 / etc (2012-6610)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to Firefox 12.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-May/079461.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a56d390"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-May/079462.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?99eef311"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-May/079463.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d27c865"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-May/079464.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97232ce2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-Gtk2-MozEmbed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^15([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 15.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC15", reference:"firefox-12.0-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"gnome-python2-extras-2.25.3-35.fc15.7")) flag++;
if (rpm_check(release:"FC15", reference:"perl-Gtk2-MozEmbed-0.09-1.fc15.11")) flag++;
if (rpm_check(release:"FC15", reference:"xulrunner-12.0-1.fc15")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / gnome-python2-extras / perl-Gtk2-MozEmbed / xulrunner");
}
