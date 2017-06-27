#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-8627.
#

include("compat.inc");

if (description)
{
  script_id(55427);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/20 22:15:24 $");

  script_xref(name:"FEDORA", value:"2011-8627");

  script_name(english:"Fedora 15 : firefox-5.0-1.fc15 / gjs-0.7.14-6.fc15 / gnome-python2-extras-2.25.3-32.fc15 / etc (2011-8627)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to new upstream Firefox version 5.0, fixing multiple security
issues detailed in the upstream advisories :

  -
    http://www.mozilla.org/security/known-vulnerabilities/fi
    refox.html#firefox5

See upstream release notes for more information about this new 
version :

  - http://www.mozilla.com/en-US/firefox/5.0/releasenotes/

This update ALSO contains a change to the GNOME 3 shell's gjs library,
to make it use the standalone js package, to reduce risk of
regression.

It also includes all packages depending on gecko-libs rebuilt against
the new version of Firefox / XULRunner.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.com/en-US/firefox/5.0/releasenotes/"
  );
  # http://www.mozilla.org/security/known-vulnerabilities/firefox.html#firefox5
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9382419d"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=676437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=715188"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-June/061970.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bdc0c331"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-June/061971.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a35b15a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-June/061972.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b21004fc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-June/061973.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc44064e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-June/061974.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ea647456"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-June/061975.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0604f721"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-June/061976.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?59ee0806"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-June/061977.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb144b17"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:js");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozvoikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-Gtk2-MozEmbed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/27");
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
if (! ereg(pattern:"^15([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 15.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC15", reference:"firefox-5.0-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"gjs-0.7.14-6.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"gnome-python2-extras-2.25.3-32.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"gnome-shell-3.0.2-3.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"js-1.8.5-6.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"mozvoikko-1.9.0-5.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"perl-Gtk2-MozEmbed-0.09-1.fc15.1")) flag++;
if (rpm_check(release:"FC15", reference:"xulrunner-5.0-2.fc15")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / gjs / gnome-python2-extras / gnome-shell / js / mozvoikko / etc");
}
