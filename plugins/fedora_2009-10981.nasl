#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-10981.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(42383);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/08 20:21:54 $");

  script_cve_id("CVE-2009-0689", "CVE-2009-3274", "CVE-2009-3370", "CVE-2009-3372", "CVE-2009-3373", "CVE-2009-3374", "CVE-2009-3375", "CVE-2009-3376", "CVE-2009-3380", "CVE-2009-3382");
  script_bugtraq_id(36851, 36852, 36853, 36855, 36856, 36857, 36858, 36866, 36867, 36871);
  script_xref(name:"FEDORA", value:"2009-10981");

  script_name(english:"Fedora 10 : Miro-2.0.5-5.fc10 / blam-1.8.5-15.fc10 / epiphany-2.24.3-11.fc10 / etc (2009-10981)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to new upstream Firefox version 3.0.15, fixing multiple
security issues detailed in the upstream advisories:
http://www.mozilla.org/security/known-
vulnerabilities/firefox30.html#firefox3.0.15 Update also includes all
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
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=524815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=530151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=530155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=530156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=530157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=530162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=530167"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=530168"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=530567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=530569"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-November/030609.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71282852"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-November/030610.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a9e9ccc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-November/030611.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?495f6c34"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-November/030612.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6df7dccd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-November/030613.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9405d31b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-November/030614.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8b4f63c9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-November/030615.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4cc43fc7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-November/030616.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb83670b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-November/030617.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?32590090"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-November/030618.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?805b9cb9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-November/030619.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8e8d8cd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-November/030620.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dd0643f6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-November/030621.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c53043c5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-November/030622.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d2f47676"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-November/030623.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb04f81f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-November/030624.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c45a42f1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-November/030625.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?524d8492"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-November/030626.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?891c4281"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-November/030627.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f97b1c2a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:Miro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:blam");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-Gtk2-MozEmbed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gnome2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/05");
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
if (rpm_check(release:"FC10", reference:"Miro-2.0.5-5.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"blam-1.8.5-15.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"epiphany-2.24.3-11.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"epiphany-extensions-2.24.3-6.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"evolution-rss-0.1.4-5.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"firefox-3.0.15-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"galeon-2.0.7-15.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gecko-sharp2-0.13-13.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gnome-python2-extras-2.19.1-35.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gnome-web-photo-0.3-23.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"google-gadgets-0.10.5-11.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kazehakase-0.5.6-4.fc10.7")) flag++;
if (rpm_check(release:"FC10", reference:"mozvoikko-0.9.5-15.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"mugshot-1.2.2-14.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"pcmanx-gtk2-0.3.8-14.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"perl-Gtk2-MozEmbed-0.08-6.fc10.6")) flag++;
if (rpm_check(release:"FC10", reference:"ruby-gnome2-0.19.3-3.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"xulrunner-1.9.0.15-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"yelp-2.24.0-14.fc10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Miro / blam / epiphany / epiphany-extensions / evolution-rss / etc");
}
