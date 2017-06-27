#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-8279.
#

include("compat.inc");

if (description)
{
  script_id(40483);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/08 20:21:56 $");

  script_cve_id("CVE-2009-2470", "CVE-2009-2654", "CVE-2009-2662", "CVE-2009-2663", "CVE-2009-2664", "CVE-2009-2665");
  script_bugtraq_id(35803, 35927, 35928);
  script_xref(name:"FEDORA", value:"2009-8279");

  script_name(english:"Fedora 11 : kazehakase-0.5.6-11.svn3771_trunk.fc11.4 / Miro-2.0.5-3.fc11 / blam-1.8.5-13.fc11 / etc (2009-8279)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to new upstream Firefox version 3.5.2, fixing multiple security
issues detailed in the upstream advisories:
http://www.mozilla.org/security/known-
vulnerabilities/firefox35.html#firefox3.5.2 Update also includes all
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
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027467.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5411894"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027468.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?def1e37b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027469.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f53394a9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027470.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ddda2adf"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027471.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?72dba140"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027472.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fab171fa"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027473.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c1118018"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027474.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb534fee"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027475.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?129fda96"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027476.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de1b481f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027477.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e9a4f1b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027478.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a08809ce"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027479.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dfa76f24"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027480.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cbe3877c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027481.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a06a305"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027482.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?38556d6e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027483.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d618274"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027484.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f84db6b0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027485.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4c131a96"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 94, 119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:Miro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:blam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chmsee");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozvoikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-Gtk2-MozEmbed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gnome2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:seahorse-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/05");
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
if (rpm_check(release:"FC11", reference:"Miro-2.0.5-3.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"blam-1.8.5-13.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"chmsee-1.0.1-10.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"epiphany-2.26.3-3.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"epiphany-extensions-2.26.1-5.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"evolution-rss-0.1.2-12.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"firefox-3.5.2-2.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"galeon-2.0.7-13.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"gnome-python2-extras-2.25.3-6.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"gnome-web-photo-0.7-5.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"google-gadgets-0.11.0-3.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"hulahop-0.4.9-7.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kazehakase-0.5.6-11.svn3771_trunk.fc11.4")) flag++;
if (rpm_check(release:"FC11", reference:"mozvoikko-0.9.7-0.6.rc1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"perl-Gtk2-MozEmbed-0.08-6.fc11.4")) flag++;
if (rpm_check(release:"FC11", reference:"ruby-gnome2-0.19.1-1.fc11.1")) flag++;
if (rpm_check(release:"FC11", reference:"seahorse-plugins-2.26.2-4.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"xulrunner-1.9.1.2-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"yelp-2.26.0-6.fc11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Miro / blam / chmsee / epiphany / epiphany-extensions / etc");
}
