#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-549.
#

include("compat.inc");

if (description)
{
  script_id(25375);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/10/21 22:04:02 $");

  script_xref(name:"FEDORA", value:"2007-549");

  script_name(english:"Fedora Core 6 : devhelp-0.12-11.fc6 / epiphany-2.16.3-5.fc6 / firefox-1.5.0.12-1.fc6 / etc (2007-549)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix several security bugs are now
available Fedora Core 6.

This update has been rated as having critical security impact by the
Fedora Security Response Team.

Mozilla Firefox is an open source Web browser.

Several flaws were found in the way Firefox processed certain
malformed JavaScript code. A web page containing malicious JavaScript
code could cause Firefox to crash or potentially execute arbitrary
code as the user running Firefox. (CVE-2007-2867, CVE-2007-2868)

A flaw was found in the way Firefox handled certain FTP PASV commands.
A malicious FTP server could use this flaw to perform a rudimentary
port-scan of machines behind a user's firewall. (CVE-2007-1562)

Several denial of service flaws were found in the way Firefox handled
certain form and cookie data. A malicious website that is able to set
arbitrary form and cookie data could prevent Firefox from functioning
properly. (CVE-2007-1362, CVE-2007-2869)

A flaw was found in the way Firefox handled the addEventListener
JavaScript method. A malicious website could use this method to access
or modify sensitive data from another website. (CVE-2007-2870)

A flaw was found in the way Firefox displayed certain web content. A
malicious web page could generate content that would overlay user
interface elements such as the hostname and security indicators,
tricking users into thinking they are visiting a different site.
(CVE-2007-2871)

Users of Firefox are advised to upgrade to these erratum packages,
which contain Firefox version 1.5.0.12 that corrects these issues.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-May/001760.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1de6e105"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-May/001761.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b9b4fe22"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-May/001762.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cbcc4a71"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-May/001763.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e5318d2e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:devhelp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 6.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC6", reference:"devhelp-0.12-11.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"devhelp-debuginfo-0.12-11.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"devhelp-devel-0.12-11.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"epiphany-2.16.3-5.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"epiphany-debuginfo-2.16.3-5.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"epiphany-devel-2.16.3-5.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"firefox-1.5.0.12-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"firefox-debuginfo-1.5.0.12-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"firefox-devel-1.5.0.12-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"yelp-2.16.0-13.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"yelp-debuginfo-2.16.0-13.fc6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "devhelp / devhelp-debuginfo / devhelp-devel / epiphany / etc");
}
