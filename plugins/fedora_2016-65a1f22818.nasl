#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2016-65a1f22818.
#

include("compat.inc");

if (description)
{
  script_id(89800);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/03/10 15:12:11 $");

  script_xref(name:"FEDORA", value:"2016-65a1f22818");

  script_name(english:"Fedora 23 : community-mysql-5.6.29-1.fc23 (2016-65a1f22818)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is an update to 5.6.29 that delivers also all fixes for
CVE-2015-4766, CVE-2015-4791, CVE-2015-4792, CVE-2015-4800,
CVE-2015-4802, CVE-2015-4807, CVE-2015-4815, CVE-2015-4819,
CVE-2015-4826, CVE-2015-4830, CVE-2015-4833, CVE-2015-4836,
CVE-2015-4858, CVE-2015-4861, CVE-2015-4862, CVE-2015-4864,
CVE-2015-4866, CVE-2015-4870, CVE-2015-4879, CVE-2015-4890,
CVE-2015-4895, CVE-2015-4904, CVE-2015-4905, CVE-2015-4910,
CVE-2015-4913, CVE-2015-7744, CVE-2016-0502, CVE-2016-0503,
CVE-2016-0504, CVE-2016-0505, CVE-2016-0546, CVE-2016-0594,
CVE-2016-0595, CVE-2016-0596, CVE-2016-0597, CVE-2016-0598,
CVE-2016-0599, CVE-2016-0600, CVE-2016-0601, CVE-2016-0605,
CVE-2016-0606, CVE-2016-0607, CVE-2016-0608, CVE-2016-0609,
CVE-2016-0610, CVE-2016-0611, CVE-2016-0616 (some of them were fixed
in previous update already).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1267776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1276223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1301517"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-March/178643.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9c0cc30c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected community-mysql package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:community-mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:23");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC23", reference:"community-mysql-5.6.29-1.fc23")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "community-mysql");
}
