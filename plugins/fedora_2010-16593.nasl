#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-16593.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(50356);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/20 21:13:52 $");

  script_cve_id("CVE-2010-3175", "CVE-2010-3176", "CVE-2010-3177", "CVE-2010-3178", "CVE-2010-3179", "CVE-2010-3180", "CVE-2010-3182", "CVE-2010-3183");
  script_bugtraq_id(44243, 44245, 44247, 44248, 44249, 44251, 44252, 44253);
  script_xref(name:"FEDORA", value:"2010-16593");

  script_name(english:"Fedora 13 : firefox-3.6.11-1.fc13 / galeon-2.0.7-34.fc13 / gnome-python2-extras-2.25.3-23.fc13 / etc (2010-16593)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to new upstream Firefox version 3.6.11, fixing multiple
security issues detailed in the upstream advisories :

http://www.mozilla.org/security/known-vulnerabilities/firefox36.html#f
irefox3.6.11

Update also includes all packages depending on gecko-libs rebuilt
against new version of Firefox / XULRunner.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://www.mozilla.org/security/known-vulnerabilities/firefox36.html#firefox3.6.11
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ebdf7518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=642272"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=642275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=642277"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=642283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=642286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=642290"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=642294"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=642300"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-October/049829.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4ae1e85"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-October/049830.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b115b82"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-October/049831.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bcf76dcb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-October/049832.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0aba3310"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-October/049833.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4bea5fe2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-October/049834.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a0b91fe2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-October/049835.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e41d79b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:galeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-web-photo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozvoikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-Gtk2-MozEmbed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:13");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^13([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 13.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC13", reference:"firefox-3.6.11-1.fc13")) flag++;
if (rpm_check(release:"FC13", reference:"galeon-2.0.7-34.fc13")) flag++;
if (rpm_check(release:"FC13", reference:"gnome-python2-extras-2.25.3-23.fc13")) flag++;
if (rpm_check(release:"FC13", reference:"gnome-web-photo-0.9-13.fc13")) flag++;
if (rpm_check(release:"FC13", reference:"mozvoikko-1.0-15.fc13")) flag++;
if (rpm_check(release:"FC13", reference:"perl-Gtk2-MozEmbed-0.08-6.fc13.18")) flag++;
if (rpm_check(release:"FC13", reference:"xulrunner-1.9.2.11-1.fc13")) flag++;


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
