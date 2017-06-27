#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-1398.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(37378);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/08 20:21:54 $");

  script_cve_id("CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0354", "CVE-2009-0355", "CVE-2009-0356", "CVE-2009-0357", "CVE-2009-0358");
  script_xref(name:"FEDORA", value:"2009-1398");

  script_name(english:"Fedora 10 : Miro-1.2.8-2.fc10 / blam-1.8.5-6.fc10 / devhelp-0.22-3.fc10 / epiphany-2.24.3-2.fc10 / etc (2009-1398)");
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
against the new version, including the latest google gadgets upstream
release. See http://code.google.com/p/google-gadgets-for-
linux/source/browse/trunk/ChangeLog?spec=svn1087&r=1087 for details.
Note: after the updated packages are installed, Firefox must be
restarted for the update to take effect.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://code.google.com/p/google-gadgets-for-"
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
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019860.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa2be989"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019861.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1cda3f42"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019862.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fcbe9f3e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019863.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a95e5672"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019864.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?978d15da"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019865.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7416bd6e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019866.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?daf01537"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019867.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cbcafdc7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019868.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4d0513d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019869.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e798b57d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019870.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dceef152"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019871.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b741398c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019872.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ed80716"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019873.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f732be59"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019874.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f5caeec8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019875.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d3ac6de2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019876.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a89b71d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019877.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?49c2de53"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-February/019878.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a689b718"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(59, 79, 200, 264, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/06");
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
if (rpm_check(release:"FC10", reference:"Miro-1.2.8-2.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"blam-1.8.5-6.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"devhelp-0.22-3.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"epiphany-2.24.3-2.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"epiphany-extensions-2.24.0-4.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"evolution-rss-0.1.2-4.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"firefox-3.0.6-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"galeon-2.0.7-5.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gecko-sharp2-0.13-4.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gnome-python2-extras-2.19.1-26.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gnome-web-photo-0.3-14.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"google-gadgets-0.10.5-2.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kazehakase-0.5.6-1.fc10.3")) flag++;
if (rpm_check(release:"FC10", reference:"mozvoikko-0.9.5-6.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"mugshot-1.2.2-5.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"pcmanx-gtk2-0.3.8-5.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"ruby-gnome2-0.18.1-3.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"xulrunner-1.9.0.6-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"yelp-2.24.0-5.fc10")) flag++;


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
