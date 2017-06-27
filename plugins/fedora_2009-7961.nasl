#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-7961.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(40358);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/08 20:21:55 $");

  script_cve_id("CVE-2009-2462", "CVE-2009-2463", "CVE-2009-2464", "CVE-2009-2465", "CVE-2009-2466", "CVE-2009-2467", "CVE-2009-2469", "CVE-2009-2471", "CVE-2009-2472");
  script_xref(name:"FEDORA", value:"2009-7961");

  script_name(english:"Fedora 10 : Miro-2.0.5-2.fc10 / blam-1.8.5-12.fc10 / devhelp-0.22-10.fc10 / epiphany-2.24.3-8.fc10 / etc (2009-7961)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to new upstream Firefox version 3.0.12, fixing multiple
security issues detailed in the upstream advisories:
http://www.mozilla.org/security/known-
vulnerabilities/firefox30.html#firefox3.0.12 Update also includes all
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
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=512128"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=512131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=512133"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=512135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=512136"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=512137"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=512142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=512146"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=512147"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026940.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a9dd026a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026941.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4244bed7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026942.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?81496686"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026943.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9dd95c64"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026944.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af86fc95"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026945.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6bf4edb3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026946.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?acc83ba7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026947.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2604ba8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026952.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?70f0f671"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026953.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?40146428"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026954.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a6cbcfa"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026955.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4cf0b532"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026956.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78440d72"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026957.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6c01baf"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026958.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?411702c7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026959.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b58dabbd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026961.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d1a96ef"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026962.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0e609dc6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(79, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:Miro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:blam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/24");
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
if (rpm_check(release:"FC10", reference:"Miro-2.0.5-2.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"blam-1.8.5-12.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"devhelp-0.22-10.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"epiphany-2.24.3-8.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"evolution-rss-0.1.2-8.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"firefox-3.0.12-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"galeon-2.0.7-12.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gecko-sharp2-0.13-10.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gnome-python2-extras-2.19.1-32.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gnome-web-photo-0.3-20.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"google-gadgets-0.10.5-8.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kazehakase-0.5.6-4.fc10.4")) flag++;
if (rpm_check(release:"FC10", reference:"mozvoikko-0.9.5-12.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"mugshot-1.2.2-11.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"pcmanx-gtk2-0.3.8-11.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"ruby-gnome2-0.19.0-3.fc10.1")) flag++;
if (rpm_check(release:"FC10", reference:"xulrunner-1.9.0.12-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"yelp-2.24.0-11.fc10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Miro / blam / devhelp / epiphany / evolution-rss / firefox / galeon / etc");
}
