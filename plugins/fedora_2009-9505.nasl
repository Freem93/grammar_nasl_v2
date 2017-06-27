#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-9505.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(40956);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/08 20:21:56 $");

  script_cve_id("CVE-2009-3069", "CVE-2009-3070", "CVE-2009-3071", "CVE-2009-3072", "CVE-2009-3073", "CVE-2009-3074", "CVE-2009-3075", "CVE-2009-3077", "CVE-2009-3078", "CVE-2009-3079");
  script_bugtraq_id(36343);
  script_xref(name:"FEDORA", value:"2009-9505");

  script_name(english:"Fedora 11 : Miro-2.5.2-4.fc11 / blam-1.8.5-14.fc11 / chmsee-1.0.1-11.fc11 / eclipse-3.4.2-15.fc11 / etc (2009-9505)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to new upstream Firefox version 3.5.3, fixing multiple security
issues detailed in the upstream advisories:
http://www.mozilla.org/security/known-
vulnerabilities/firefox35.html#firefox3.5.3 Update also includes all
packages depending on gecko-libs rebuilt against new version of
Firefox / XULRunner.

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
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=521684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=521686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=521687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=521688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=521689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=521690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=521691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=521693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=521694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=521695"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029025.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?70409101"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029026.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51935936"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029027.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b20ebddd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029028.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?502281b9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029029.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6d719d8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029030.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?38e2e3be"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029031.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85bc3083"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029032.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ee81c6b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029033.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?660e73cc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029034.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d0d7362e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029035.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2cc84ae1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029036.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3688de7d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029037.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a926f2ef"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029038.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f153ff0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029039.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?831e3887"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029040.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?94c220af"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029041.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?41d6ea9c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029042.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dccee672"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029043.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7c9f936e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029044.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f8b43456"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029046.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f44a937"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029047.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?72796f39"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:Miro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:blam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chmsee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:eclipse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:evolution-rss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:galeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-web-photo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:google-gadgets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:hulahop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kazehakase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:monodevelop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozvoikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pcmanx-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-Gtk2-MozEmbed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gnome2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:seahorse-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/14");
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
if (! ereg(pattern:"^11([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 11.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC11", reference:"Miro-2.5.2-4.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"blam-1.8.5-14.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"chmsee-1.0.1-11.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"eclipse-3.4.2-15.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"epiphany-2.26.3-4.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"epiphany-extensions-2.26.1-6.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"evolution-rss-0.1.4-3.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"firefox-3.5.3-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"galeon-2.0.7-14.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"gnome-python2-extras-2.25.3-7.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"gnome-web-photo-0.7-6.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"google-gadgets-0.11.0-5.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"hulahop-0.4.9-8.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kazehakase-0.5.7-2.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"monodevelop-2.0-5.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"mozvoikko-0.9.7-0.7.rc1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"pcmanx-gtk2-0.3.8-8.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"perl-Gtk2-MozEmbed-0.08-6.fc11.5")) flag++;
if (rpm_check(release:"FC11", reference:"ruby-gnome2-0.19.1-2.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"seahorse-plugins-2.26.2-5.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"xulrunner-1.9.1.3-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"yelp-2.26.0-7.fc11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Miro / blam / chmsee / eclipse / epiphany / epiphany-extensions / etc");
}
