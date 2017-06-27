#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-7898.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(40347);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/12/08 20:21:55 $");

  script_cve_id("CVE-2009-2477", "CVE-2009-2478", "CVE-2009-2479");
  script_bugtraq_id(35660, 35707);
  script_xref(name:"FEDORA", value:"2009-7898");

  script_name(english:"Fedora 11 : kazehakase-0.5.6-11.svn3771_trunk.fc11.3 / Miro-2.0.5-2.fc11 / blam-1.8.5-12.fc11 / etc (2009-7898)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to new upstream Firefox version 3.5.1, fixing multiple security
issues detailed in the upstream advisories:
http://www.mozilla.org/security/known-
vulnerabilities/firefox35.html#firefox3.5.1 Update also includes all
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
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=511228"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026829.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4dd5e68"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026830.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c39626ea"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026831.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?516373f1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026832.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?35f8f173"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026833.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c9cf6fc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026834.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5868543c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026835.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d7aa3f7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026836.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c17131d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026837.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?39187779"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026838.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?54b8571c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026839.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2d134e44"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026840.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5892c8e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026841.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4125ee3f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026842.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7dbcd608"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026843.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eee125d3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026844.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?099355bd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026845.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa7e1869"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026846.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?188401d2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026847.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f89eae2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026848.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f5a3b49c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 3.5 escape() Return Value Memory Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94, 119, 189);

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kazehakase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozvoikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-Gtk2-MozEmbed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gnome2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/23");
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
if (rpm_check(release:"FC11", reference:"Miro-2.0.5-2.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"blam-1.8.5-12.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"chmsee-1.0.1-9.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"eclipse-3.4.2-13.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"epiphany-2.26.3-2.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"epiphany-extensions-2.26.1-4.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"evolution-rss-0.1.2-11.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"firefox-3.5.1-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"galeon-2.0.7-12.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"gnome-python2-extras-2.25.3-5.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"gnome-web-photo-0.7-4.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"google-gadgets-0.11.0-2.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"hulahop-0.4.9-6.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"java-1.6.0-openjdk-1.6.0.0-25.b16.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kazehakase-0.5.6-11.svn3771_trunk.fc11.3")) flag++;
if (rpm_check(release:"FC11", reference:"mozvoikko-0.9.7-0.5.rc1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"perl-Gtk2-MozEmbed-0.08-6.fc11.3")) flag++;
if (rpm_check(release:"FC11", reference:"ruby-gnome2-0.19.0-3.fc11.1")) flag++;
if (rpm_check(release:"FC11", reference:"xulrunner-1.9.1.1-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"yelp-2.26.0-5.fc11")) flag++;


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
