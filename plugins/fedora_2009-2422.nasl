#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-2422.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(36866);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/08 20:21:55 $");

  script_cve_id("CVE-2009-0771", "CVE-2009-0772", "CVE-2009-0773", "CVE-2009-0774", "CVE-2009-0775", "CVE-2009-0776", "CVE-2009-0777");
  script_bugtraq_id(33990);
  script_xref(name:"FEDORA", value:"2009-2422");

  script_name(english:"Fedora 10 : Miro-2.0-4.fc10 / blam-1.8.5-7.fc10 / devhelp-0.22-5.fc10 / epiphany-2.24.3-3.fc10 / etc (2009-2422)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to the new upstream Firefox 3.0.7 / XULRunner 1.9.0.7 fixing
multiple security issues: http://www.mozilla.org/security/known-
vulnerabilities/firefox30.html#firefox3.0.7 This update also contains
new builds of all applications depending on Gecko libraries, built
against the new version. Note: after the updated packages are
installed, Firefox must be restarted for the update to take effect.

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
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=488272"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=488273"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=488276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=488283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=488287"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=488290"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=488292"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021020.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ac3134c1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021021.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ccd5046b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021022.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0e5e85e3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021023.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2d5427c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021024.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75412765"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021025.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a990b00"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021026.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f7ba4e71"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021027.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c3029c4e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021028.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ac5eca80"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021029.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c920e98f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021030.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f6fd4e1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021031.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4017b115"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021032.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d879d95f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021033.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?45763728"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021034.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?09401bb3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021035.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?288009bc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021036.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d0a32d8e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021037.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?066368ea"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021038.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7b3650cd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 200, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/08");
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
if (rpm_check(release:"FC10", reference:"Miro-2.0-4.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"blam-1.8.5-7.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"devhelp-0.22-5.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"epiphany-2.24.3-3.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"epiphany-extensions-2.24.0-5.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"evolution-rss-0.1.2-5.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"firefox-3.0.7-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"galeon-2.0.7-7.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gecko-sharp2-0.13-5.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gnome-python2-extras-2.19.1-27.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gnome-web-photo-0.3-15.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"google-gadgets-0.10.5-3.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kazehakase-0.5.6-1.fc10.4")) flag++;
if (rpm_check(release:"FC10", reference:"mozvoikko-0.9.5-7.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"mugshot-1.2.2-6.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"pcmanx-gtk2-0.3.8-6.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"ruby-gnome2-0.18.1-4.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"xulrunner-1.9.0.7-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"yelp-2.24.0-6.fc10")) flag++;


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
