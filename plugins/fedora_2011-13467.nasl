#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-13467.
#

include("compat.inc");

if (description)
{
  script_id(56371);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/20 21:56:28 $");

  script_osvdb_id(75834, 75835, 75837, 75838, 75839, 75840, 75841);
  script_xref(name:"FEDORA", value:"2011-13467");

  script_name(english:"Fedora 14 : firefox-3.6.23-1.fc14 / galeon-2.0.7-44.fc14.1 / gnome-python2-extras-2.25.3-34.fc14.1 / etc (2011-13467)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to new upstream Firefox version 3.6.23, fixing multiple
security issues detailed in the upstream advisories :

  -
    http://www.mozilla.org/security/known-vulnerabilities/fi
    refox36.html#firefox3.6.23

This update also includes all packages depending on gecko-libs rebuilt
against the new version of Firefox / XULRunner.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://www.mozilla.org/security/known-vulnerabilities/firefox36.html#firefox3.6.23
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a347de35"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067088.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4842549a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067089.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe42ddea"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067090.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a85f4c5c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067091.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c77fb179"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067092.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?87f1fcef"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067093.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8573a4b6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-October/067094.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f6e5477e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:galeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-web-photo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozvoikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-Gtk2-MozEmbed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^14([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 14.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC14", reference:"firefox-3.6.23-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"galeon-2.0.7-44.fc14.1")) flag++;
if (rpm_check(release:"FC14", reference:"gnome-python2-extras-2.25.3-34.fc14.1")) flag++;
if (rpm_check(release:"FC14", reference:"gnome-web-photo-0.9-24.fc14.1")) flag++;
if (rpm_check(release:"FC14", reference:"mozvoikko-1.0-25.fc14.1")) flag++;
if (rpm_check(release:"FC14", reference:"perl-Gtk2-MozEmbed-0.08-6.fc14.30")) flag++;
if (rpm_check(release:"FC14", reference:"xulrunner-1.9.2.23-1.fc14")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / galeon / gnome-python2-extras / gnome-web-photo / etc");
}
