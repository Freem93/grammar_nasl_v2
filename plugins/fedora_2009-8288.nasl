#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-8288.
#

include("compat.inc");

if (description)
{
  script_id(40484);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/08 20:21:56 $");

  script_cve_id("CVE-2009-2470", "CVE-2009-2654", "CVE-2009-2662", "CVE-2009-2663", "CVE-2009-2664", "CVE-2009-2665");
  script_bugtraq_id(35803, 35927, 35928);
  script_xref(name:"FEDORA", value:"2009-8288");

  script_name(english:"Fedora 10 : Miro-2.0.5-3.fc10 / blam-1.8.5-13.fc10 / epiphany-2.24.3-9.fc10 / etc (2009-8288)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to new upstream Firefox version 3.0.13, fixing multiple
security issues detailed in the upstream advisories:
http://www.mozilla.org/security/known-vulnerabilities/firefox30.html#f
irefox3.0.13 Update also includes all packages depending on gecko-libs
rebuilt against new version of Firefox / XULRunner. Note: Issues
described in MFSA 2009-42 and MFSA 2009-43 were previously addressed
via rebase of the NSS packages.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027514.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?16c75bf6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027515.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef9c9c85"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027516.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?05980972"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027517.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f685d331"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027518.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0354abc1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027519.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6395dd56"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027520.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bbdcae2b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027521.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9be5bde1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027522.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a3d352de"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027523.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0dc362f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027524.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c39c5a31"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027525.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82b08faf"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027526.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fbd84d7b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027527.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a467d30"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027528.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1cf19a6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027529.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0d1aa1b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027530.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e7987091"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027531.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2ec59fd1"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-Gtk2-MozEmbed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gnome2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:10");

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
if (! ereg(pattern:"^10([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 10.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC10", reference:"Miro-2.0.5-3.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"blam-1.8.5-13.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"epiphany-2.24.3-9.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"evolution-rss-0.1.2-9.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"firefox-3.0.13-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"galeon-2.0.7-13.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gecko-sharp2-0.13-11.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gnome-python2-extras-2.19.1-33.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gnome-web-photo-0.3-21.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"google-gadgets-0.10.5-9.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kazehakase-0.5.6-4.fc10.5")) flag++;
if (rpm_check(release:"FC10", reference:"mozvoikko-0.9.5-13.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"mugshot-1.2.2-12.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"pcmanx-gtk2-0.3.8-12.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"perl-Gtk2-MozEmbed-0.08-6.fc10.4")) flag++;
if (rpm_check(release:"FC10", reference:"ruby-gnome2-0.19.1-1.fc10.1")) flag++;
if (rpm_check(release:"FC10", reference:"xulrunner-1.9.0.13-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"yelp-2.24.0-12.fc10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Miro / blam / epiphany / evolution-rss / firefox / galeon / etc");
}
