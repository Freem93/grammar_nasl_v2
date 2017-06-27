#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2004-530.
#

include("compat.inc");

if (description)
{
  script_id(15930);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:09:32 $");

  script_xref(name:"FEDORA", value:"2004-530");

  script_name(english:"Fedora Core 2 : mysql-3.23.58-9.1 (2004-530)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Tue Oct 12 2004 Tom Lane <tgl at redhat.com> 3.23.58-9.1

  - fix security issues CVE-2004-0835, CVE-2004-0836,
    CVE-2004-0837 (bugs #135372, 135375, 135387)

  - fix privilege escalation on GRANT ALL ON `Foo\_Bar`
    (CVE-2004-0957)

    - fix multilib problem with mysqlbug and mysql_config

    - adjust chkconfig priority per bug #128852

    - remove bogus quoting per bug #129409 (MySQL 4.0 has
      done likewise)

    - add sleep to mysql.init restart(); may or may not fix
      bug #133993

    - fix low-priority security issues CVE-2004-0388,
      CVE-2004-0381, CVE-2004-0457 (bugs #119442, 125991,
      130347, 130348)

  - fix bug with dropping databases under recent kernels
    (bug #124352)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2004-December/000481.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ded8ed2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mysql-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^2([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 2.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC2", reference:"mysql-3.23.58-9.1")) flag++;
if (rpm_check(release:"FC2", reference:"mysql-bench-3.23.58-9.1")) flag++;
if (rpm_check(release:"FC2", reference:"mysql-debuginfo-3.23.58-9.1")) flag++;
if (rpm_check(release:"FC2", reference:"mysql-devel-3.23.58-9.1")) flag++;
if (rpm_check(release:"FC2", reference:"mysql-server-3.23.58-9.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql / mysql-bench / mysql-debuginfo / mysql-devel / mysql-server");
}
