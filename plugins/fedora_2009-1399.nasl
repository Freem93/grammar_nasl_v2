#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-1399.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(35604);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/08 20:21:55 $");

  script_cve_id("CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0354", "CVE-2009-0355", "CVE-2009-0356", "CVE-2009-0357", "CVE-2009-0358");
  script_bugtraq_id(33598);
  script_xref(name:"FEDORA", value:"2009-1399");

  script_name(english:"Fedora 9 : Miro-1.2.7-4.fc9 / blam-1.8.5-5.fc9.1 / cairo-dock-1.6.3.1-1.fc9.3 / chmsee-1.0.1-8.fc9 / etc (2009-1399)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to the new upstream Firefox 3.0.6 / XULRunner 1.9.0.6 fixing
multiple security issues: http://www.mozilla.org/security/known-
vulnerabilities/firefox30.html#firefox3.0.6 This update also contains
new builds of all applications depending on Gecko libraries, built
against the new version. Note: after the updated packages are
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
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=483139"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=483141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=483142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=483143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=483144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=483145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=483150"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019880.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c9a8f0b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019881.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71d06cef"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019882.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2f1d1c94"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019883.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6852586f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019884.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4fd64aaa"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019885.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e442a7bf"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019886.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f9453aca"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019887.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?054b9fb0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019888.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ca793bd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019889.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b4888d89"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019890.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?86d08533"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019891.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a17494d8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019892.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4d7dc182"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d42d3fb9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019894.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c3035d85"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019895.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc23934b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019896.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb468341"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019897.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cdeb1882"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019898.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c747eb43"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019899.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4940e57"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019900.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0efd33a1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59, 79, 200, 264, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC9", reference:"Miro-1.2.7-4.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"blam-1.8.5-5.fc9.1")) flag++;
if (rpm_check(release:"FC9", reference:"cairo-dock-1.6.3.1-1.fc9.3")) flag++;
if (rpm_check(release:"FC9", reference:"chmsee-1.0.1-8.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"devhelp-0.19.1-8.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"epiphany-2.22.2-7.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"epiphany-extensions-2.22.1-7.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"evolution-rss-0.1.0-6.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"firefox-3.0.6-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"galeon-2.0.7-5.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"gnome-python2-extras-2.19.1-23.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"gnome-web-photo-0.3-17.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"google-gadgets-0.10.5-2.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"gtkmozembedmm-1.4.2.cvs20060817-25.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"kazehakase-0.5.6-1.fc9.3")) flag++;
if (rpm_check(release:"FC9", reference:"mozvoikko-0.9.5-6.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"mugshot-1.2.2-5.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"ruby-gnome2-0.17.0-5.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"totem-2.23.2-10.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"xulrunner-1.9.0.6-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"yelp-2.22.1-8.fc9")) flag++;


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
