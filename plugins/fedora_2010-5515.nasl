#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-5515.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(47394);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/20 21:38:17 $");

  script_cve_id("CVE-2010-0174", "CVE-2010-0175", "CVE-2010-0176", "CVE-2010-0177", "CVE-2010-0178");
  script_bugtraq_id(39122, 39123, 39125, 39128, 39133, 39137);
  script_xref(name:"FEDORA", value:"2010-5515");

  script_name(english:"Fedora 11 : Miro-2.5.4-3.fc11 / blam-1.8.5-19.fc11 / chmsee-1.0.1-16.fc11 / epiphany-2.26.3-9.fc11 / etc (2010-5515)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to new upstream Firefox version 3.5.9 / XULRunner version
1.9.1.9, fixing multiple security issues detailed in the upstream
advisories: http://www.mozilla.org/security/known-
vulnerabilities/firefox35.html#firefox3.5.9 Update also includes all
packages depending on gecko-libs rebuilt against new version of
Firefox / XULRunner. CVE-2010-0173 CVE-2010-0174 CVE-2010-0175
CVE-2010-0176 CVE-2010-0177 CVE-2010-0178 CVE-2010-0181

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
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=578147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=578149"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=578150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=578152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=578154"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/038333.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?43bfddc5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/038334.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f589881"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/038335.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f6e0735"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/038336.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c7c49f2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/038337.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d48fc57"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/038338.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd4ccac8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/038339.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e4b3782"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/038340.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?95dc08cc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/038341.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb363a01"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/038342.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b3c4c13e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/038343.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66ed8041"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/038344.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e4a362e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/038345.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58b09b76"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/038346.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fbd33f02"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/038347.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?119ac7aa"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/038348.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6d6a242d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/038349.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2cb4ec06"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/038350.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a3d36c9b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pcmanx-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-Gtk2-MozEmbed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC11", reference:"Miro-2.5.4-3.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"blam-1.8.5-19.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"chmsee-1.0.1-16.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"epiphany-2.26.3-9.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"epiphany-extensions-2.26.1-11.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"evolution-rss-0.1.4-11.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"firefox-3.5.9-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"galeon-2.0.7-22.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"gnome-python2-extras-2.25.3-12.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"gnome-web-photo-0.7-11.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"google-gadgets-0.11.1-6.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"hulahop-0.4.9-13.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kazehakase-0.5.8-5.fc11.1")) flag++;
if (rpm_check(release:"FC11", reference:"mozvoikko-0.9.7-0.12.rc1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"pcmanx-gtk2-0.3.9-4.20100222svn.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"perl-Gtk2-MozEmbed-0.08-6.fc11.10")) flag++;
if (rpm_check(release:"FC11", reference:"xulrunner-1.9.1.9-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"yelp-2.26.0-12.fc11")) flag++;


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
