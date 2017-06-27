#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-4078.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(38188);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/10/21 22:41:47 $");

  script_cve_id("CVE-2009-1313");
  script_bugtraq_id(34743);
  script_xref(name:"FEDORA", value:"2009-4078");

  script_name(english:"Fedora 9 : Miro-2.0.3-4.fc9 / blam-1.8.5-9.fc9.1 / chmsee-1.0.1-12.fc9 / devhelp-0.19.1-12.fc9 / etc (2009-4078)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to Firefox 3.0.10 fixing one security issue:
http://www.mozilla.org/security/known-
vulnerabilities/firefox30.html#firefox3.0.10 Depending packages
rebuilt against new Firefox are also included in this update.
Additional bugs fixed in other packages: - totem: Fix YouTube plugin
following website changes

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
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=497447"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022857.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e236031"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022858.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?debd626c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022859.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5b92eafa"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022860.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?edfc00ba"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022861.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58b96841"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022862.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6f89911a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022863.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67ff97fe"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022864.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64537ca1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022865.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd7615df"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022866.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d6821722"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022867.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d5cdda96"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022868.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?31dc6bac"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022869.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?21bf2f52"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022870.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9e996865"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022871.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bfed81b8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022872.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7c54f2a2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022873.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b7d14153"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022874.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7aa829ed"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022875.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6283d339"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022876.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d0e430a1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:Miro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:blam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chmsee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:evolution-rss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:galeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-web-photo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:google-gadgets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gtkmozembedmm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kazehakase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozvoikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mugshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gnome2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:totem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 9.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC9", reference:"Miro-2.0.3-4.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"blam-1.8.5-9.fc9.1")) flag++;
if (rpm_check(release:"FC9", reference:"chmsee-1.0.1-12.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"devhelp-0.19.1-12.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"epiphany-2.22.2-11.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"epiphany-extensions-2.22.1-11.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"evolution-rss-0.1.0-11.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"firefox-3.0.10-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"galeon-2.0.7-10.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"gnome-python2-extras-2.19.1-27.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"gnome-web-photo-0.3-21.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"google-gadgets-0.10.5-6.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"gtkmozembedmm-1.4.2.cvs20060817-29.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"kazehakase-0.5.6-4.fc9.2")) flag++;
if (rpm_check(release:"FC9", reference:"mozvoikko-0.9.5-10.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"mugshot-1.2.2-9.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"ruby-gnome2-0.17.0-9.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"totem-2.23.2-16.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"xulrunner-1.9.0.10-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"yelp-2.22.1-12.fc9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Miro / blam / chmsee / devhelp / epiphany / epiphany-extensions / etc");
}
