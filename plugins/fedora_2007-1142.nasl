#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-1142.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(27693);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 21:54:54 $");

  script_cve_id("CVE-2007-3089", "CVE-2007-3656", "CVE-2007-3734", "CVE-2007-3735", "CVE-2007-3736", "CVE-2007-3737", "CVE-2007-3738");
  script_xref(name:"FEDORA", value:"2007-1142");

  script_name(english:"Fedora 7 : firefox-2.0.0.5-1.fc7 (2007-1142)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox is an open source web browser, designed for standards
compliance, performance and portability.

Several flaws were found in the way Firefox processed certain
malformed JavaScript code. A web page containing malicious JavaScript
code could cause Firefox to crash or potentially execute arbitrary
code as the user running Firefox. (CVE-2007-3734, CVE-2007-3735)

Several flaws were found in the way Firefox handles certain JavaScript
code. A web page containing malicious JavaScript code could inject
arbitrary content into other web pages. (CVE-2007-3736, CVE-2007-3089)

A flaw was found in the way Firefox cached web pages on the local
disk. A malicious web page may be able to inject arbitrary HTML into a
browsing session if the user reloads a targeted site. (CVE-2007-3656)

A flaw was found in the way Firefox processes certain web content. A
web page containing malicious content could execute arbitrary commands
as the user running Firefox. (CVE-2007-3737, CVE-2007-3738)

Users of Firefox are advised to upgrade to these erratum packages,
which contain patches that correct these issues.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-July/002804.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f7b431d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected firefox, firefox-debuginfo and / or firefox-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/06");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"firefox-2.0.0.5-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"firefox-debuginfo-2.0.0.5-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"firefox-devel-2.0.0.5-1.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / firefox-debuginfo / firefox-devel");
}
