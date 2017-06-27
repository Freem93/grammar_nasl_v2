#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-1936.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(47288);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/08 20:31:53 $");

  script_cve_id("CVE-2009-1571", "CVE-2009-3988", "CVE-2010-0159", "CVE-2010-0160", "CVE-2010-0162");
  script_xref(name:"FEDORA", value:"2010-1936");

  script_name(english:"Fedora 11 : Miro-2.5.4-2.fc11 / blam-1.8.5-18.fc11 / chmsee-1.0.1-15.fc11 / eclipse-3.4.2-20.fc11 / etc (2010-1936)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to new upstream Firefox version 3.5.8, fixing multiple security
issues detailed in the upstream advisories:
http://www.mozilla.org/security/known-
vulnerabilities/firefox35.html#firefox3.5.8

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
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=566047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=566049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=566050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=566051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=566052"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-February/035348.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e22457d4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-February/035349.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a4963399"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-February/035350.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7ec2032"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-February/035351.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f2e1aef"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-February/035352.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b116f4e7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-February/035353.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b7b42529"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-February/035354.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3af1f66e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-February/035355.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a8a6599"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-February/035356.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07519c0d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-February/035357.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1b7f66c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-February/035358.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db205d55"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-February/035359.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4dda7581"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-February/035360.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1da96e83"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-February/035361.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e872d5af"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-February/035362.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a80ee6f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-February/035363.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f3eb2b87"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-February/035364.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1cb7a6d7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-February/035365.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a23df2a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-February/035366.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9baba1ae"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-February/035367.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef199f2f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-February/035368.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3273517b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(79, 94, 264, 399);

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC11", reference:"Miro-2.5.4-2.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"blam-1.8.5-18.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"chmsee-1.0.1-15.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"eclipse-3.4.2-20.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"epiphany-2.26.3-8.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"epiphany-extensions-2.26.1-10.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"evolution-rss-0.1.4-10.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"firefox-3.5.8-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"galeon-2.0.7-20.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"gnome-python2-extras-2.25.3-11.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"gnome-web-photo-0.7-10.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"google-gadgets-0.11.1-5.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"hulahop-0.4.9-12.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kazehakase-0.5.8-5.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"monodevelop-2.0-9.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"mozvoikko-0.9.7-0.11.rc1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"pcmanx-gtk2-0.3.9-2.20100210svn.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"perl-Gtk2-MozEmbed-0.08-6.fc11.9")) flag++;
if (rpm_check(release:"FC11", reference:"ruby-gnome2-0.19.3-6.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"xulrunner-1.9.1.8-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"yelp-2.26.0-11.fc11")) flag++;


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
