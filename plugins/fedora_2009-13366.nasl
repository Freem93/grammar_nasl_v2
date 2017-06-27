#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-13366.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43339);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/08 20:21:54 $");

  script_cve_id("CVE-2009-3388", "CVE-2009-3389", "CVE-2009-3979", "CVE-2009-3980", "CVE-2009-3982", "CVE-2009-3983", "CVE-2009-3984", "CVE-2009-3985", "CVE-2009-3986");
  script_xref(name:"FEDORA", value:"2009-13366");

  script_name(english:"Fedora 12 : Miro-2.5.2-7.fc12 / blam-1.8.5-21.fc12 / firefox-3.5.6-1.fc12 / galeon-2.0.7-19.fc12 / etc (2009-13366)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to new upstream Firefox version 3.5.6, fixing multiple security
issues detailed in the upstream advisories:
http://www.mozilla.org/security/known-
vulnerabilities/firefox35.html#firefox3.5.6 Update also includes all
packages depending on gecko-libs rebuilt against new version of
Firefox / XULRunner. CVE-2009-3979 CVE-2009-3980 CVE-2009-3982
CVE-2009-3983 CVE-2009-3984 CVE-2009-3985 CVE-2009-3986 CVE-2009-3388
CVE-2009-3389

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
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=546694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=546720"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=546722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=546724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=546726"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-December/032850.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b2d5481"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-December/032851.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f928a2f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-December/032852.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?94113072"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-December/032853.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?357b8c71"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-December/032854.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d72d5e20"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-December/032855.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?14bfdbc4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-December/032856.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?28e7a2ad"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-December/032858.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?273b888e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-December/032860.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6fac847e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(94, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:Miro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:blam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:galeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-web-photo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozvoikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-Gtk2-MozEmbed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/18");
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
if (! ereg(pattern:"^12([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 12.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC12", reference:"Miro-2.5.2-7.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"blam-1.8.5-21.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"firefox-3.5.6-1.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"galeon-2.0.7-19.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"gnome-python2-extras-2.25.3-14.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"gnome-web-photo-0.9-4.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"mozvoikko-1.0-7.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"perl-Gtk2-MozEmbed-0.08-6.fc12.10")) flag++;
if (rpm_check(release:"FC12", reference:"xulrunner-1.9.1.6-1.fc12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Miro / blam / firefox / galeon / gnome-python2-extras / etc");
}
