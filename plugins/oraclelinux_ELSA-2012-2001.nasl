#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2012-2001.
#

include("compat.inc");

if (description)
{
  script_id(68668);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/20 14:21:43 $");

  script_cve_id("CVE-2010-2962", "CVE-2012-0056");
  script_bugtraq_id(44067, 51625);

  script_name(english:"Oracle Linux 5 / 6 : Unbreakable Enterprise kernel (ELSA-2012-2001)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

* Improved fix for CVE-2010-2962.

The original upstream fix for CVE-2010-2962 had an overflow bug in its
bounds checking.


* CVE-2012-0056: Privilege escalation in /proc/[pid]/mem writing.

It was found that permissions were not checked properly in the Linux
kernel when handling the /proc/[pid]/mem writing functionality.  A
local, unprivileged user could use this flaw to escalate their
privileges.

[2.6.32-300.7.1.el6uek]
- Revert 'proc: enable writing to /proc/pid/mem' [orabug 13619701] 
{CVE-2012-0056}
- [PATCH] x86, tsc: Skip TSC synchronization checks for tsc=reliable 
(Suresh Siddha)

[2.6.32-300.6.1.el6uek]
- tracing: Fix NULL pointer deref with SEND_SIG_FORCED (Oleg Nesterov) 
[orabug 13611655]

[2.6.32-300.5.1.el6uek]
- sched, x86: Avoid unnecessary overflow in sched_clock (Salman Qazi) 
[orabug 13604567]
- [x86]: Don't resume/restore cpu if not of the expected cpu (Joe Jin) 
[orabug 13492670]
- drm/i915: Rephrase pwrite bounds checking to avoid any potential 
overflow (Chris Wilson) [CVE-2010-296]
- x2apic: Enable the bios request for x2apic optout (Suresh Siddha) 
[orabug 13565303]
- fuse: split queues to scale I/O throughput (Srinivas Eeda) [orabug 
10004611]
- fuse: break fc spinlock (Srinivas Eeda) [orabug 10004611]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-January/002572.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-January/002573.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-300.7.1.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-300.7.1.el6uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-300.7.1.el5uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-300.7.1.el5uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-300.7.1.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-300.7.1.el6uekdebug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-2.6.32-300.7.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-debug-2.6.32-300.7.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-devel-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-debug-devel-2.6.32-300.7.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-devel-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-devel-2.6.32-300.7.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-doc-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-doc-2.6.32-300.7.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-firmware-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-firmware-2.6.32-300.7.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-headers-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-headers-2.6.32-300.7.1.el5uek")) flag++;
if (rpm_check(release:"EL5", reference:"ofa-2.6.32-300.7.1.el5uek-1.5.1-4.0.53")) flag++;
if (rpm_check(release:"EL5", reference:"ofa-2.6.32-300.7.1.el5uekdebug-1.5.1-4.0.53")) flag++;

if (rpm_exists(release:"EL6", rpm:"kernel-uek-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-2.6.32-300.7.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-debug-2.6.32-300.7.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-debug-devel-2.6.32-300.7.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-devel-2.6.32-300.7.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-doc-2.6.32-300.7.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-firmware-2.6.32-300.7.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-headers-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-headers-2.6.32-300.7.1.el6uek")) flag++;
if (rpm_check(release:"EL6", reference:"mlnx_en-2.6.32-300.7.1.el6uek-1.5.7-0.1")) flag++;
if (rpm_check(release:"EL6", reference:"mlnx_en-2.6.32-300.7.1.el6uekdebug-1.5.7-0.1")) flag++;
if (rpm_check(release:"EL6", reference:"ofa-2.6.32-300.7.1.el6uek-1.5.1-4.0.47")) flag++;
if (rpm_check(release:"EL6", reference:"ofa-2.6.32-300.7.1.el6uekdebug-1.5.1-4.0.47")) flag++;


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
