#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-6491.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(33539);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/08 20:21:53 $");

  script_cve_id("CVE-2008-2785", "CVE-2008-2933");
  script_bugtraq_id(29802, 30242);
  script_xref(name:"FEDORA", value:"2008-6491");

  script_name(english:"Fedora 8 : Miro-1.2.3-3.fc8 / blam-1.8.3-17.fc8 / cairo-dock-1.6.1.1-1.fc8.1 / chmsee-1.0.0-3.31.fc8 / etc (2008-6491)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix several security issues are now
available for Fedora 8. An integer overflow flaw was found in the way
Firefox displayed certain web content. A malicious website could cause
Firefox to crash, or execute arbitrary code with the permissions of
the user running Firefox. (CVE-2008-2785) A flaw was found in the way
Firefox handled certain command line URLs. If another application
passed Firefox a malformed URL, it could result in Firefox executing
local malicious content with chrome privileges. (CVE-2008-2933)
Updated packages update Mozilla Firefox to upstream version 2.0.0.16
to address these flaws: http://www.mozilla.org/security/known-
vulnerabilities/firefox20.html#firefox2.0.0.16 This update also
contains blam, cairo-dock, chmsee, devhelp, epiphany,
epiphany-extensions, galeon, gnome- python2-extras, gnome-web-photo,
gtkmozembedmm, kazehakase, liferea, Miro, openvrml, ruby-gnome2 and
yelp packages rebuilt against new Firefox / Gecko libraries.

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
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=452204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=454697"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012553.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a3b6f8e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012554.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ec9e6bb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012555.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e01f1cb6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012556.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4372fcdb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012557.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51d27fad"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012558.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a47ec31"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012559.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dfe87787"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012560.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d5fbfe29"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012561.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?48b791b9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012562.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c726b1d6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012563.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71ee7abc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012564.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?476ec4c3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012565.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca7535ac"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012566.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ef6b6b5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012567.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f0d929a1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012568.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6658669d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012569.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc904475"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:Miro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:blam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:cairo-dock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chmsee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:galeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-web-photo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gtkmozembedmm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kazehakase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:liferea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvrml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gnome2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 8.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC8", reference:"Miro-1.2.3-3.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"blam-1.8.3-17.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"cairo-dock-1.6.1.1-1.fc8.1")) flag++;
if (rpm_check(release:"FC8", reference:"chmsee-1.0.0-3.31.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"devhelp-0.16.1-9.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"epiphany-2.20.3-6.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"epiphany-extensions-2.20.1-9.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"firefox-2.0.0.16-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"galeon-2.0.4-4.fc8.3")) flag++;
if (rpm_check(release:"FC8", reference:"gnome-python2-extras-2.19.1-16.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gnome-web-photo-0.3-12.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gtkmozembedmm-1.4.2.cvs20060817-22.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"kazehakase-0.5.4-2.fc8.3")) flag++;
if (rpm_check(release:"FC8", reference:"liferea-1.4.15-3.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"openvrml-0.17.6-6.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"ruby-gnome2-0.17.0-0.3.rc1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"yelp-2.20.0-11.fc8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Miro / blam / cairo-dock / chmsee / devhelp / epiphany / etc");
}
