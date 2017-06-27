#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-5430.
#

include("compat.inc");

if (description)
{
  script_id(33222);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/05 16:01:14 $");

  script_cve_id("CVE-2008-1806", "CVE-2008-1807", "CVE-2008-1808");
  script_bugtraq_id(29639, 29640, 29641);
  script_xref(name:"FEDORA", value:"2008-5430");

  script_name(english:"Fedora 8 : freetype-2.3.5-4.fc8 (2008-5430)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update backports security fixes from upstream version 2.3.6 -
CVE-2008-1806, CVE-2008-1807 and CVE-2008-1808. For further details,
see:
http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=7
15
http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=7
16
http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=7
17 Note: TTF bytecode interpreter is not enabled by default in the
Fedora freetype packages, therefore Fedora packages were not affected
by the TTF part of the CVE-2008-1808.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=715
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?df6643e2"
  );
  # http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=716
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b88a321"
  );
  # http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=717
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b75c39d1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=450768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=450773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=450774"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-June/011464.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa9b6ad4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freetype package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:freetype");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/19");
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
if (rpm_check(release:"FC8", reference:"freetype-2.3.5-4.fc8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freetype");
}
