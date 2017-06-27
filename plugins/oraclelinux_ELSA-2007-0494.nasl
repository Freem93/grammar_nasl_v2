#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0494 and 
# Oracle Linux Security Advisory ELSA-2007-0494 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67522);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/26 16:04:31 $");

  script_cve_id("CVE-2007-2022");
  script_bugtraq_id(23437);
  script_osvdb_id(34140);
  script_xref(name:"RHSA", value:"2007:0494");

  script_name(english:"Oracle Linux 3 / 4 / 5 : kdebase (ELSA-2007-0494)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0494 :

Updated kdebase packages that resolve an interaction security issue
with Adobe Flash Player are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kdebase packages provide the core applications for KDE, the K
Desktop Environment. These core packages include Konqueror, the web
browser and file manager.

A problem with the interaction between the Flash Player and the
Konqueror web browser was found. The problem could lead to key presses
leaking to the Flash Player applet instead of the browser
(CVE-2007-2022).

Users of Konqueror who have installed the Adobe Flash Player plugin
should upgrade to these updated packages, which contain a patch
provided by Dirk Muller that protects against this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-June/000172.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-June/000184.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-June/000222.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdebase packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdebase-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL3", cpu:"i386", reference:"kdebase-3.1.3-5.16.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"kdebase-3.1.3-5.16.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"kdebase-devel-3.1.3-5.16.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"kdebase-devel-3.1.3-5.16.0.1")) flag++;

if (rpm_check(release:"EL4", cpu:"i386", reference:"kdebase-3.3.1-5.19.rhel4.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"kdebase-3.3.1-5.19.rhel4.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"kdebase-devel-3.3.1-5.19.rhel4.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"kdebase-devel-3.3.1-5.19.rhel4.0.1")) flag++;

if (rpm_check(release:"EL5", reference:"kdebase-3.5.4-13.6.el5.0.1")) flag++;
if (rpm_check(release:"EL5", reference:"kdebase-devel-3.5.4-13.6.el5.0.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdebase / kdebase-devel");
}
