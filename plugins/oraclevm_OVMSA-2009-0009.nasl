#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2009-0009.
#

include("compat.inc");

if (description)
{
  script_id(79456);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2008-4307", "CVE-2009-0342", "CVE-2009-0343", "CVE-2009-0834", "CVE-2009-1336", "CVE-2009-1337");
  script_bugtraq_id(33417, 33951, 34405);

  script_name(english:"OracleVM 2.1 : kernel (OVMSA-2009-0009)");
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

CVE-2008-4307 Race condition in the do_setlk function in fs/nfs/file.c
in the Linux kernel before 2.6.26 allows local users to cause a denial
of service (crash) via vectors resulting in an interrupted RPC call
that leads to a stray FL_POSIX lock, related to improper handling of a
race between fcntl and close in the EINTR case.

CVE-2009-1337 The exit_notify function in kernel/exit.c in the Linux
kernel before 2.6.30-rc1 does not restrict exit signals when the
CAP_KILL capability is held, which allows local users to send an
arbitrary signal to a process by running a program that modifies the
exit_signal field and then uses an exec system call to launch a setuid
application.

CVE-2009-0834 The audit_syscall_entry function in the Linux kernel
2.6.28.7 and earlier on the x86_64 platform does not properly handle
(1) a 32-bit process making a 64-bit syscall or (2) a 64-bit process
making a 32-bit syscall, which allows local users to bypass certain
syscall audit configurations via crafted syscalls, a related issue to
CVE-2009-0342 and CVE-2009-0343.

CVE-2009-1336 fs/nfs/client.c in the Linux kernel before 2.6.23 does
not properly initialize a certain structure member that stores the
maximum NFS filename length, which allows local users to cause a
denial of service (OOPS) via a long filename, related to the
encode_lookup function.

  - CVE-2008-4307 -[nfs] remove bogus lock-if-signalled case
    (Bryn M. Reeves) [456287 456288]

  - CVE-2009-1337 - [misc] exit_notify: kill the wrong
    capable check 

  - CVE-2009-0834 - [ptrace] audit_syscall_entry to use
    right syscall number (Jiri Pirko) [488001 488002]

  - CVE-2009-1336 - [nfs] v4: client crash on file lookup
    with long names (Sachin S. Prabhu) [494078 493942]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2009-May/000023.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 264, 362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-BOOT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-BOOT-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-ovs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-ovs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/18");
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
if (rpm_check(release:"OVS2.1", reference:"kernel-BOOT-2.6.18-8.1.15.1.32.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"kernel-BOOT-devel-2.6.18-8.1.15.1.32.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"kernel-kdump-2.6.18-8.1.15.1.32.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"kernel-kdump-devel-2.6.18-8.1.15.1.32.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"kernel-ovs-2.6.18-8.1.15.1.32.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"kernel-ovs-devel-2.6.18-8.1.15.1.32.el5")) flag++;

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
