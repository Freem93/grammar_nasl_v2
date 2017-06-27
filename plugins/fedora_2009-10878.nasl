#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-10878.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(42297);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/08 20:21:54 $");

  script_cve_id("CVE-2009-0689", "CVE-2009-3274", "CVE-2009-3370", "CVE-2009-3372", "CVE-2009-3373", "CVE-2009-3374", "CVE-2009-3375", "CVE-2009-3376", "CVE-2009-3380");
  script_xref(name:"FEDORA", value:"2009-10878");

  script_name(english:"Fedora 11 : Miro-2.5.2-5.fc11 / blam-1.8.5-15.fc11 / chmsee-1.0.1-12.fc11 / eclipse-3.4.2-17.fc11 / etc (2009-10878)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to new upstream Firefox version 3.5.4, fixing multiple security
issues detailed in the upstream advisories:
http://www.mozilla.org/security/known-
vulnerabilities/firefox35.html#firefox3.5.4 Update also includes all
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
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030460.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9990574d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030461.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ea3a660"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030462.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9da39c92"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030463.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?01e7b130"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030464.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bca2e40b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030465.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4fcf2516"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030466.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d11e095"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030467.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2d24099d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030468.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d0e62233"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030469.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?005d9ce7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030470.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ebff9bdb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030471.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3106a132"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030472.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d37b51fd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030473.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7e8cbc12"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030474.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1246cf37"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030475.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f9e52713"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030476.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b0a35cb7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030477.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33574a8b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030478.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?89a1035d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030479.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8dd7f9f7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030480.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a908698f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-October/030481.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b58cb4d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(16, 119, 264);

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:seahorse-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/29");
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
if (rpm_check(release:"FC11", reference:"Miro-2.5.2-5.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"blam-1.8.5-15.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"chmsee-1.0.1-12.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"eclipse-3.4.2-17.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"epiphany-2.26.3-5.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"epiphany-extensions-2.26.1-7.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"evolution-rss-0.1.4-5.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"firefox-3.5.4-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"galeon-2.0.7-17.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"gnome-python2-extras-2.25.3-8.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"gnome-web-photo-0.7-7.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"google-gadgets-0.11.1-2.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"hulahop-0.4.9-9.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"kazehakase-0.5.8-2.fc11.1")) flag++;
if (rpm_check(release:"FC11", reference:"monodevelop-2.0-6.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"mozvoikko-0.9.7-0.8.rc1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"pcmanx-gtk2-0.3.8-9.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"perl-Gtk2-MozEmbed-0.08-6.fc11.6")) flag++;
if (rpm_check(release:"FC11", reference:"ruby-gnome2-0.19.3-3.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"seahorse-plugins-2.26.2-7.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"xulrunner-1.9.1.4-1.fc11")) flag++;
if (rpm_check(release:"FC11", reference:"yelp-2.26.0-8.fc11")) flag++;


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
