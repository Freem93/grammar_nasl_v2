#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-12750.
#

include("compat.inc");

if (description)
{
  script_id(85317);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2015/11/10 15:23:00 $");

  script_cve_id("CVE-2015-2213", "CVE-2015-5730", "CVE-2015-5731", "CVE-2015-5732", "CVE-2015-5733", "CVE-2015-5734");
  script_xref(name:"FEDORA", value:"2015-12750");

  script_name(english:"Fedora 23 : wordpress-4.2.4-1.fc23 (2015-12750)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**WordPress 4.2.4 Security and Maintenance Release**

WordPress 4.2.4 is now available. This is a security release for all
previous versions and we strongly encourage you to update your sites
immediately.

This release addresses six issues, including three cross-site
scripting vulnerabilities and a potential SQL injection that could be
used to compromise a site, which were discovered by Marc-Alexandre
Montpas of Sucuri, Helen Hou-Sandi of the WordPress security team,
Netanel Rubin of Check Point, and Ivan Grigorov. It also includes a
fix for a potential timing side-channel attack, discovered by Johannes
Schmitt of Scrutinizer, and prevents an attacker from locking a post
from being edited, discovered by Mohamed A. Baset.

Our thanks to those who have practiced responsible disclosure of
security issues.

WordPress 4.2.4 also fixes four bugs. For more information, see: the
release notes or consult the list of changes.

  - the release notes:
    https://codex.wordpress.org/Version_4.2.4

    - the list of changes:
      https://core.trac.wordpress.org/log/branches/4.2?rev=3
      3573&stop_rev=33396

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1250583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://codex.wordpress.org/Version_4.2.4"
  );
  # https://core.trac.wordpress.org/log/branches/4.2?rev=33573&stop_rev=33396
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?661d9776"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-August/163481.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?48864ac9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wordpress package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:23");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^23([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 23.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC23", reference:"wordpress-4.2.4-1.fc23")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wordpress");
}
