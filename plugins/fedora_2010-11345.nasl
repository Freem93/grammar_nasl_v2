#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-11345.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(47809);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/20 21:05:30 $");

  script_cve_id("CVE-2010-0654", "CVE-2010-1205", "CVE-2010-1206", "CVE-2010-1207", "CVE-2010-1208", "CVE-2010-1209", "CVE-2010-1210", "CVE-2010-1211", "CVE-2010-1212", "CVE-2010-1213", "CVE-2010-1214", "CVE-2010-1215", "CVE-2010-2751", "CVE-2010-2752", "CVE-2010-2753", "CVE-2010-2754");
  script_xref(name:"FEDORA", value:"2010-11345");

  script_name(english:"Fedora 13 : firefox-3.6.7-1.fc13 / galeon-2.0.7-30.fc13 / gnome-python2-extras-2.25.3-20.fc13 / etc (2010-11345)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to new upstream Firefox version 3.6.7, fixing multiple security
issues detailed in the upstream advisories:
http://www.mozilla.org/security/known-
vulnerabilities/firefox36.html#firefox3.6.7 Update also includes all
packages depending on gecko-libs rebuilt against new version of
Firefox / XULRunner. CVE-2010-1211 CVE-2010-1212 CVE-2010-1208
CVE-2010-1209 CVE-2010-1214 CVE-2010-1215 CVE-2010-2752 CVE-2010-2753
CVE-2010-1205 CVE-2010-1213 CVE-2010-1207 CVE-2010-1210 CVE-2010-1206
CVE-2010-2751 CVE-2010-0654 CVE-2010-2754

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
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=568231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=608238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=608763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=615455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=615456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=615458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=615459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=615462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=615463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=615464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=615466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=615471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=615472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=615474"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=615480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=615488"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-July/044448.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?935981f2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-July/044449.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5cbae3e5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-July/044450.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a518e6b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-July/044451.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9affd7a3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-July/044452.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?181d2dc8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-July/044453.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?955a18cb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-July/044454.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc3febed"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:galeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-web-photo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozvoikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-Gtk2-MozEmbed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:13");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/23");
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
if (! ereg(pattern:"^13([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 13.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC13", reference:"firefox-3.6.7-1.fc13")) flag++;
if (rpm_check(release:"FC13", reference:"galeon-2.0.7-30.fc13")) flag++;
if (rpm_check(release:"FC13", reference:"gnome-python2-extras-2.25.3-20.fc13")) flag++;
if (rpm_check(release:"FC13", reference:"gnome-web-photo-0.9-10.fc13")) flag++;
if (rpm_check(release:"FC13", reference:"mozvoikko-1.0-12.fc13")) flag++;
if (rpm_check(release:"FC13", reference:"perl-Gtk2-MozEmbed-0.08-6.fc13.15")) flag++;
if (rpm_check(release:"FC13", reference:"xulrunner-1.9.2.7-1.fc13")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / galeon / gnome-python2-extras / gnome-web-photo / etc");
}
