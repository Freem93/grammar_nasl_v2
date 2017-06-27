#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-5430.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(82956);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/19 23:14:51 $");

  script_cve_id("CVE-2015-1806", "CVE-2015-1807", "CVE-2015-1808", "CVE-2015-1809", "CVE-2015-1810", "CVE-2015-1811", "CVE-2015-1812", "CVE-2015-1813", "CVE-2015-1814");
  script_xref(name:"FEDORA", value:"2015-5430");

  script_name(english:"Fedora 22 : jenkins-1.606-1.fc22 / jenkins-executable-war-1.29-4.fc22 / jffi-1.2.7-5.fc22 (2015-5430)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security fix for CVE-2015-1806, CVE-2015-1807, CVE-2015-1813,
CVE-2015-1812, CVE-2015-1810, CVE-2015-1808, CVE-2015-1809,
CVE-2015-1814, CVE-2015-1811

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1205615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1205616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1205620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1205622"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1205623"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1205625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1205627"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1205632"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-April/155396.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?40be8b1d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-April/155397.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e7410a2e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-April/155398.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb0eef2e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected jenkins, jenkins-executable-war and / or jffi
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jenkins-executable-war");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jffi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/22");
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
if (! ereg(pattern:"^22([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 22.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC22", reference:"jenkins-1.606-1.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"jenkins-executable-war-1.29-4.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"jffi-1.2.7-5.fc22")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jenkins / jenkins-executable-war / jffi");
}
