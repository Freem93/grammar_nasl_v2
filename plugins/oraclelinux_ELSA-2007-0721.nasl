#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0721 and 
# Oracle Linux Security Advisory ELSA-2007-0721 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67545);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/12/01 16:16:27 $");

  script_cve_id("CVE-2007-3388");
  script_bugtraq_id(25154);
  script_osvdb_id(39385);
  script_xref(name:"RHSA", value:"2007:0721");

  script_name(english:"Oracle Linux 3 / 4 / 5 : qt (ELSA-2007-0721)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0721 :

Updated qt packages that correct an integer overflow flaw are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Qt is a software toolkit that simplifies the task of writing and
maintaining GUI (Graphical User Interface) applications for the X
Window System.

Several format string flaws were found in Qt error message handling.
If an application linked against Qt created an error message from
user-supplied data in a certain way, it could lead to a denial of
service or possibly allow the execution of arbitrary code.
(CVE-2007-3388)

Users of Qt should upgrade to these updated packages, which contain a
backported patch to correct these issues.

Red Hat would like to acknowledge Tim Brown of Portcullis Computer
Security and Dirk Mueller for these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-July/000293.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-July/000294.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-July/000295.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qt packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt-MySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt-ODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt-PostgreSQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt-devel-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"qt-3.1.2-16.RHEL3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"qt-3.1.2-16.RHEL3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"qt-MySQL-3.1.2-16.RHEL3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"qt-MySQL-3.1.2-16.RHEL3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"qt-ODBC-3.1.2-16.RHEL3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"qt-ODBC-3.1.2-16.RHEL3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"qt-config-3.1.2-16.RHEL3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"qt-config-3.1.2-16.RHEL3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"qt-designer-3.1.2-16.RHEL3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"qt-designer-3.1.2-16.RHEL3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"qt-devel-3.1.2-16.RHEL3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"qt-devel-3.1.2-16.RHEL3")) flag++;

if (rpm_check(release:"EL4", cpu:"i386", reference:"qt-3.3.3-11.RHEL4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"qt-3.3.3-11.RHEL4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"qt-MySQL-3.3.3-11.RHEL4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"qt-MySQL-3.3.3-11.RHEL4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"qt-ODBC-3.3.3-11.RHEL4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"qt-ODBC-3.3.3-11.RHEL4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"qt-PostgreSQL-3.3.3-11.RHEL4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"qt-PostgreSQL-3.3.3-11.RHEL4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"qt-config-3.3.3-11.RHEL4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"qt-config-3.3.3-11.RHEL4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"qt-designer-3.3.3-11.RHEL4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"qt-designer-3.3.3-11.RHEL4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"qt-devel-3.3.3-11.RHEL4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"qt-devel-3.3.3-11.RHEL4")) flag++;

if (rpm_check(release:"EL5", reference:"qt-3.3.6-21.el5")) flag++;
if (rpm_check(release:"EL5", reference:"qt-MySQL-3.3.6-21.el5")) flag++;
if (rpm_check(release:"EL5", reference:"qt-ODBC-3.3.6-21.el5")) flag++;
if (rpm_check(release:"EL5", reference:"qt-PostgreSQL-3.3.6-21.el5")) flag++;
if (rpm_check(release:"EL5", reference:"qt-config-3.3.6-21.el5")) flag++;
if (rpm_check(release:"EL5", reference:"qt-designer-3.3.6-21.el5")) flag++;
if (rpm_check(release:"EL5", reference:"qt-devel-3.3.6-21.el5")) flag++;
if (rpm_check(release:"EL5", reference:"qt-devel-docs-3.3.6-21.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qt / qt-MySQL / qt-ODBC / qt-PostgreSQL / qt-config / qt-designer / etc");
}
