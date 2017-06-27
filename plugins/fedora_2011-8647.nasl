#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-8647.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(55545);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/11 13:32:16 $");

  script_bugtraq_id(48319, 48357, 48358, 48360, 48361, 48365, 48366, 48367, 48368, 48369, 48371, 48372, 48373, 48375, 48376, 48379, 48380);
  script_xref(name:"FEDORA", value:"2011-8647");

  script_name(english:"Fedora 14 : firefox-3.6.18-1.fc14 / galeon-2.0.7-41.fc14.1 / gnome-python2-extras-2.25.3-31.fc14.1 / etc (2011-8647)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to new upstream Firefox version 3.6.18 and Thunderbird version
3.1.11, fixing multiple security issues detailed in the upstream
advisories :

  -
    http://www.mozilla.org/security/known-vulnerabilities/fi
    refox36.html#firefox3.6.18

    -
      http://www.mozilla.org/security/known-vulnerabilities/
      thunderbird31.html#thunderbird3.1.11

This update also includes all packages depending on gecko-libs rebuilt
against the new version of Firefox / XULRunner.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://www.mozilla.org/security/known-vulnerabilities/firefox36.html#firefox3.6.18
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5694f54a"
  );
  # http://www.mozilla.org/security/known-vulnerabilities/thunderbird31.html#thunderbird3.1.11
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?88384a07"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-July/062407.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?358e8384"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-July/062408.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6def2b2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-July/062409.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2470a5e9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-July/062410.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b3ed425"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-July/062411.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8778f4f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-July/062412.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66ef72c0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-July/062413.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b6b0d33"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-July/062414.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?991cdba2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:galeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-web-photo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozvoikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-Gtk2-MozEmbed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC14", reference:"firefox-3.6.18-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"galeon-2.0.7-41.fc14.1")) flag++;
if (rpm_check(release:"FC14", reference:"gnome-python2-extras-2.25.3-31.fc14.1")) flag++;
if (rpm_check(release:"FC14", reference:"gnome-web-photo-0.9-21.fc14.1")) flag++;
if (rpm_check(release:"FC14", reference:"mozvoikko-1.0-22.fc14.1")) flag++;
if (rpm_check(release:"FC14", reference:"perl-Gtk2-MozEmbed-0.08-6.fc14.27")) flag++;
if (rpm_check(release:"FC14", reference:"thunderbird-3.1.11-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"xulrunner-1.9.2.18-1.fc14")) flag++;


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
