#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-11511.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(37149);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/08 20:11:36 $");

  script_cve_id("CVE-2008-5500", "CVE-2008-5501", "CVE-2008-5502", "CVE-2008-5505", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5510", "CVE-2008-5511", "CVE-2008-5512", "CVE-2008-5513");
  script_xref(name:"FEDORA", value:"2008-11511");

  script_name(english:"Fedora 10 : Miro-1.2.7-3.fc10 / blam-1.8.5-5.fc10 / devhelp-0.22-2.fc10 / epiphany-2.24.1-3.fc10 / etc (2008-11511)");
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
against new version. Note: after the updated packages are installed,
Firefox must be restarted for the update to take effect.

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
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017906.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?43286554"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017907.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a7662d2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017908.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a77dd53f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017909.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6ba28cd4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017910.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?45ea898b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017911.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?210e216d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017912.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d066a674"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017913.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f590d883"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017914.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa0539d2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017915.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17e9b2ff"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017916.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a3986692"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017917.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74a832de"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017918.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a083357"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017919.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a404b81d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017920.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d9414c9a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017921.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f78fd7da"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017922.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67f75152"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017923.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a6c1776"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/017924.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4e3fb15"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 79, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:Miro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:blam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:evolution-rss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:galeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gecko-sharp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-web-photo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:google-gadgets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kazehakase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozvoikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mugshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pcmanx-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gnome2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
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
if (! ereg(pattern:"^10([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 10.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC10", reference:"Miro-1.2.7-3.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"blam-1.8.5-5.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"devhelp-0.22-2.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"epiphany-2.24.1-3.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"epiphany-extensions-2.24.0-3.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"evolution-rss-0.1.2-3.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"firefox-3.0.5-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"galeon-2.0.7-4.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gecko-sharp2-0.13-3.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gnome-python2-extras-2.19.1-25.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gnome-web-photo-0.3-13.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"google-gadgets-0.10.3-2.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kazehakase-0.5.6-1.fc10.2")) flag++;
if (rpm_check(release:"FC10", reference:"mozvoikko-0.9.5-5.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"mugshot-1.2.2-4.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"pcmanx-gtk2-0.3.8-4.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"ruby-gnome2-0.18.1-2.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"xulrunner-1.9.0.5-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"yelp-2.24.0-4.fc10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Miro / blam / devhelp / epiphany / epiphany-extensions / etc");
}
