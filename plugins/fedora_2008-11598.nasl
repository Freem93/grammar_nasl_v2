#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-11598.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(35238);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/08 20:11:36 $");

  script_cve_id("CVE-2008-5500", "CVE-2008-5501", "CVE-2008-5502", "CVE-2008-5505", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5510", "CVE-2008-5511", "CVE-2008-5512", "CVE-2008-5513");
  script_bugtraq_id(32882);
  script_xref(name:"FEDORA", value:"2008-11598");

  script_name(english:"Fedora 9 : Miro-1.2.7-3.fc9 / blam-1.8.5-4.fc9.1 / cairo-dock-1.6.3.1-1.fc9.2 / chmsee-1.0.1-7.fc9 / etc (2008-11598)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to the new upstream Firefox 3.0.5 / XULRunner 1.9.0.5 fixing
multiple security issues: http://www.mozilla.org/security/known-
vulnerabilities/firefox30.html#firefox3.0.5 This update also contains
new builds of all applications depending on Gecko libraries, built
against thenew version. Note: after the updated packages are
installed, Firefox must be restarted for the update to take effect.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/known-"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=476266"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=476267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=476269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=476274"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=476278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=476280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=476281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=476283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=476285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=476287"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=476289"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017958.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?77ab19ad"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017959.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?df3d2ba8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017960.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e754e938"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017961.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?47512081"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017962.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eeca82ff"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017963.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f34716f5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017964.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0eefa5ed"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017965.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ed21dec"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017966.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a0abae5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017967.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d64c4960"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017968.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5971f84b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017969.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a8d224a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017970.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4162e726"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017971.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1fda1407"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017972.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b6f7939"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017973.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?60222e06"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017974.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cdfcb8bb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017975.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f4cce8b2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017976.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61c030a4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017977.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3b696380"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017979.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4d2d207c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 79, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:Miro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:blam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:cairo-dock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chmsee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:evolution-rss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:galeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-web-photo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:google-gadgets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gtkmozembedmm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kazehakase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozvoikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mugshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gnome2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:totem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 9.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC9", reference:"Miro-1.2.7-3.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"blam-1.8.5-4.fc9.1")) flag++;
if (rpm_check(release:"FC9", reference:"cairo-dock-1.6.3.1-1.fc9.2")) flag++;
if (rpm_check(release:"FC9", reference:"chmsee-1.0.1-7.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"devhelp-0.19.1-7.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"epiphany-2.22.2-6.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"epiphany-extensions-2.22.1-6.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"evolution-rss-0.1.0-5.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"firefox-3.0.5-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"galeon-2.0.7-4.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"gnome-python2-extras-2.19.1-22.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"gnome-web-photo-0.3-16.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"google-gadgets-0.10.3-2.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"gtkmozembedmm-1.4.2.cvs20060817-24.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"kazehakase-0.5.6-1.fc9.2")) flag++;
if (rpm_check(release:"FC9", reference:"mozvoikko-0.9.5-5.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"mugshot-1.2.2-4.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"ruby-gnome2-0.17.0-4.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"totem-2.23.2-9.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"xulrunner-1.9.0.5-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"yelp-2.22.1-7.fc9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Miro / blam / cairo-dock / chmsee / devhelp / epiphany / etc");
}
