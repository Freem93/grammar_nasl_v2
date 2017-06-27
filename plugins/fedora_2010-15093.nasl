#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-15093.
#

include("compat.inc");

if (description)
{
  script_id(49683);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/11 13:16:09 $");

  script_bugtraq_id(42654, 43091, 43092, 43093, 43095, 43096, 43097, 43100, 43101, 43102, 43104, 43106, 43108, 43118);
  script_xref(name:"FEDORA", value:"2010-15093");

  script_name(english:"Fedora 14 : firefox-3.6.10-1.fc14 / galeon-2.0.7-33.fc14 / gnome-python2-extras-2.25.3-23.fc14 / etc (2010-15093)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to new upstream Firefox version 3.6.10, fixing multiple
security issues detailed in the upstream advisories :

http://www.mozilla.org/security/known-vulnerabilities/firefox36.html#f
irefox3.6.9

Update also includes all packages depending on gecko-libs rebuilt
against new version of Firefox / XULRunner.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://www.mozilla.org/security/known-vulnerabilities/firefox36.html#firefox3.6.9
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d7c392f6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-September/048385.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af163b8a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-September/048386.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?57bb0b16"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-September/048387.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b08c3652"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-September/048388.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca9663f0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-September/048389.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e2cd7b4e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-September/048390.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ef3d8b6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-September/048391.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d40aa3a5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC14", reference:"firefox-3.6.10-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"galeon-2.0.7-33.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"gnome-python2-extras-2.25.3-23.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"gnome-web-photo-0.9-13.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"mozvoikko-1.0-14.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"perl-Gtk2-MozEmbed-0.08-6.fc14.18")) flag++;
if (rpm_check(release:"FC14", reference:"xulrunner-1.9.2.10-1.fc14")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / galeon / gnome-python2-extras / gnome-web-photo / etc");
}
