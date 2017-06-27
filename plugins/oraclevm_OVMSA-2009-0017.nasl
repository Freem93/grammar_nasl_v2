#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2009-0017.
#

include("compat.inc");

if (description)
{
  script_id(79461);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2007-5966", "CVE-2009-1389", "CVE-2009-1895");
  script_bugtraq_id(26880, 35281, 35647);
  script_osvdb_id(55807);

  script_name(english:"OracleVM 2.1 : kernel (OVMSA-2009-0017)");
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

CVE-2009-1895 The personality subsystem in the Linux kernel before
2.6.31-rc3 has a PER_CLEAR_ON_SETID setting that does not clear the
ADDR_COMPAT_LAYOUT and MMAP_PAGE_ZERO flags when executing a setuid or
setgid program, which makes it easier for local users to leverage the
details of memory usage to (1) conduct NULL pointer dereference
attacks, (2) bypass the mmap_min_addr protection mechanism, or (3)
defeat address space layout randomization (ASLR).

CVE-2007-5966 Integer overflow in the hrtimer_start function in
kernel/hrtimer.c in the Linux kernel before 2.6.23.10 allows local
users to execute arbitrary code or cause a denial of service (panic)
via a large relative timeout value. NOTE: some of these details are
obtained from third party information.

CVE-2009-1389 Buffer overflow in the RTL8169 NIC driver
(drivers/net/r8169.c) in the Linux kernel before 2.6.30 allows remote
attackers to cause a denial of service (kernel memory corruption and
crash) via a long packet.

  - [misc] personality handling: fix PER_CLEAR_ON_SETID
    (Vitaly Mayatskikh) [511173 508842] (CVE-2009-1895)

  - [misc] hrtimer: fix a soft lockup (Amerigo Wang) [418061
    418071] (CVE-2007-5966)

  - [net] r8169: fix crash when large packets are received
    (Ivan Vecera) [504731 504732] (CVE-2009-1389)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2009-August/000028.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c1bca70a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-BOOT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-BOOT-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-ovs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-ovs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/14");
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
if (rpm_check(release:"OVS2.1", reference:"kernel-BOOT-2.6.18-8.1.15.5.1.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"kernel-BOOT-devel-2.6.18-8.1.15.5.1.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"kernel-kdump-2.6.18-8.1.15.5.1.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"kernel-kdump-devel-2.6.18-8.1.15.5.1.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"kernel-ovs-2.6.18-8.1.15.5.1.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"kernel-ovs-devel-2.6.18-8.1.15.5.1.el5")) flag++;

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
