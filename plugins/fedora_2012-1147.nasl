#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-1147.
#

include("compat.inc");

if (description)
{
  script_id(57882);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/20 22:25:11 $");

  script_xref(name:"FEDORA", value:"2012-1147");

  script_name(english:"Fedora 15 : gstreamer-plugins-bad-free-0.10.22-1.fc15.1 / firefox-10.0-1.fc15 / etc (2012-1147)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Latest security update of Mozilla products and dependent packages.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-February/072956.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5965fc4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-February/072957.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?10c0c762"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-February/072958.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dba6a76a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-February/072959.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d2c90627"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-February/072960.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b9ca4539"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-February/072961.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?10843eb6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-February/072962.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7baecd0d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-February/072963.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a1243280"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gstreamer-plugins-bad-free");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libvpx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-Gtk2-MozEmbed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird-lightning");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/10");
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
if (rpm_check(release:"FC15", reference:"firefox-10.0-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"gnome-python2-extras-2.25.3-35.fc15.5")) flag++;
if (rpm_check(release:"FC15", reference:"gstreamer-plugins-bad-free-0.10.22-1.fc15.1")) flag++;
if (rpm_check(release:"FC15", reference:"libvpx-1.0.0-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"perl-Gtk2-MozEmbed-0.09-1.fc15.9")) flag++;
if (rpm_check(release:"FC15", reference:"thunderbird-10.0-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"thunderbird-lightning-1.2-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"xulrunner-10.0-1.fc15")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / gnome-python2-extras / gstreamer-plugins-bad-free / etc");
}
