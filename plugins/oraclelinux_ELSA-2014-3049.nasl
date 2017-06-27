#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2014-3049.
#

include("compat.inc");

if (description)
{
  script_id(76781);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/20 14:21:44 $");

  script_cve_id("CVE-2013-4348", "CVE-2014-4699", "CVE-2014-4943");
  script_bugtraq_id(63536, 68411, 68683);

  script_name(english:"Oracle Linux 7 : unbreakable enterprise kernel (ELSA-2014-3049)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

kernel-uek
[3.8.13-35.3.2.el7uek]
- l2tp: fix an unprivileged user to kernel privilege escalation (Sasha 
Levin)  [Orabug: 19229497]  {CVE-2014-4943} {CVE-2014-4943}
- ptrace,x86: force IRET path after a ptrace_stop() (Tejun Heo) 
[Orabug: 19230689]  {CVE-2014-4699}
- net: flow_dissector: fail on evil iph->ihl (Jason Wang)  [Orabug: 
19231234]  {CVE-2013-4348}"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-July/004296.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-3.8.13-35.3.2.el7uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"dtrace-modules-3.8.13-35.3.2.el7uek-0.4.3-4.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-3.8.13-35.3.2.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-3.8.13-35.3.2.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-devel-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-devel-3.8.13-35.3.2.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-devel-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-devel-3.8.13-35.3.2.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-doc-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-doc-3.8.13-35.3.2.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-firmware-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-firmware-3.8.13-35.3.2.el7uek")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
