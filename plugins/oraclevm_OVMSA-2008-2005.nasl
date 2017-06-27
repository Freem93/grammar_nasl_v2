#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2008-2005.
#

include("compat.inc");

if (description)
{
  script_id(79447);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2007-3104", "CVE-2007-5093", "CVE-2007-5938", "CVE-2007-6063", "CVE-2007-6282", "CVE-2007-6712", "CVE-2008-0001", "CVE-2008-0598", "CVE-2008-1294", "CVE-2008-1375", "CVE-2008-1615", "CVE-2008-2136", "CVE-2008-2358", "CVE-2008-2812");
  script_bugtraq_id(24631, 26605, 27280, 29003, 29081, 29086, 29235, 29603, 29942, 30076);

  script_name(english:"OracleVM 2.1 : kernel (OVMSA-2008-2005)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - fix utrace dead_engine ops race

  - fix ptrace_attach leak

  - CVE-2007-5093: kernel PWC driver DoS

  - CVE-2007-6282: IPSec ESP kernel panics

  - CVE-2007-6712: kernel: infinite loop in highres timers
    (kernel hang)

  - CVE-2008-1615: kernel: ptrace: Unprivileged crash on
    x86_64 %cs corruption

  - CVE-2008-1294: kernel: setrlimit(RLIMIT_CPUINFO) with
    zero value doesn't inherit properly across children

  - CVE-2008-2136: kernel: sit memory leak

  - CVE-2008-2812: kernel: NULL ptr dereference in multiple
    network drivers due to missing checks in tty code

  - restore
    linux-2.6-x86-clear-df-flag-for-signal-handlers.patch

  - restore linux-2.6-utrace.patch /
    linux-2.6-xen-utrace.patch

  - Kernel security erratas for OVM 2.1.2 from bz#5932 :

  - CVE-2007-6063: isdn: fix possible isdn_net buffer
    overflows

  - CVE-2007-3104 Null pointer to an inode in a dentry can
    cause an oops in sysfs_readdir

  - CVE-2008-0598: write system call vulnerability

  - CVE-2008-1375: kernel: race condition in dnotify

  - CVE-2008-0001: kernel: filesystem corruption by
    unprivileged user via directory truncation

  - CVE-2008-2358: dccp: sanity check feature length

  - CVE-2007-5938: NULL dereference in iwl driver

  - RHSA-2008:0508: kernel: [x86_64] The string instruction
    version didn't zero the output on exception.

  - kernel: clear df flag for signal handlers

  - fs: missing dput in do_lookup error leaks dentries

  - sysfs: fix condition check in sysfs_drop_dentry

  - sysfs: fix race condition around sd->s_dentry

  - ieee80211: off-by-two integer underflow"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2008-September/000003.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97ce6a60"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 20, 119, 189, 200, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-BOOT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-BOOT-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-ovs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-ovs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "2\.1" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 2.1", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);

flag = 0;
if (rpm_check(release:"OVS2.1", reference:"kernel-BOOT-2.6.18-8.1.15.1.19.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"kernel-BOOT-devel-2.6.18-8.1.15.1.19.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"kernel-kdump-2.6.18-8.1.15.1.19.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"kernel-kdump-devel-2.6.18-8.1.15.1.19.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"kernel-ovs-2.6.18-8.1.15.1.19.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"kernel-ovs-devel-2.6.18-8.1.15.1.19.el5")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-BOOT / kernel-BOOT-devel / kernel-kdump / kernel-kdump-devel / etc");
}
