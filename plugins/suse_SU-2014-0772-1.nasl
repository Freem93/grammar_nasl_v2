#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2014:0772-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83626);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_cve_id("CVE-2013-6382", "CVE-2013-7263", "CVE-2013-7264", "CVE-2013-7265", "CVE-2014-1737", "CVE-2014-1738");
  script_bugtraq_id(63889, 64677, 64685, 64686, 67300, 67302);

  script_name(english:"SUSE SLES10 Security Update : kernel (SUSE-SU-2014:0772-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise Server 10 Service Pack 4 LTSS kernel has
been updated to fix various security issues and several bugs.

The following security issues have been addressed :

CVE-2013-6382: Multiple buffer underflows in the XFS implementation in
the Linux kernel through 3.12.1 allow local users to cause a denial of
service (memory corruption) or possibly have unspecified other impact
by leveraging the CAP_SYS_ADMIN capability for a (1)
XFS_IOC_ATTRLIST_BY_HANDLE or (2) XFS_IOC_ATTRLIST_BY_HANDLE_32 ioctl
call with a crafted length value, related to the
xfs_attrlist_by_handle function in fs/xfs/xfs_ioctl.c and the
xfs_compat_attrlist_by_handle function in fs/xfs/xfs_ioctl32.c.
(bnc#852553)

CVE-2013-7263: The Linux kernel before 3.12.4 updates
certain length values before ensuring that associated data
structures have been initialized, which allows local users
to obtain sensitive information from kernel stack memory via
a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system call,
related to net/ipv4/ping.c, net/ipv4/raw.c, net/ipv4/udp.c,
net/ipv6/raw.c, and net/ipv6/udp.c. (bnc#857643)

CVE-2013-7264: The l2tp_ip_recvmsg function in
net/l2tp/l2tp_ip.c in the Linux kernel before 3.12.4 updates
a certain length value before ensuring that an associated
data structure has been initialized, which allows local
users to obtain sensitive information from kernel stack
memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg
system call. (bnc#857643)

CVE-2013-7265: The pn_recvmsg function in
net/phonet/datagram.c in the Linux kernel before 3.12.4
updates a certain length value before ensuring that an
associated data structure has been initialized, which allows
local users to obtain sensitive information from kernel
stack memory via a (1) recvfrom, (2) recvmmsg, or (3)
recvmsg system call. (bnc#857643)

CVE-2014-1737: The raw_cmd_copyin function in
drivers/block/floppy.c in the Linux kernel through 3.14.3
does not properly handle error conditions during processing
of an FDRAWCMD ioctl call, which allows local users to
trigger kfree operations and gain privileges by leveraging
write access to a /dev/fd device. (bnc#875798)

CVE-2014-1738: The raw_cmd_copyout function in
drivers/block/floppy.c in the Linux kernel through 3.14.3
does not properly restrict access to certain pointers during
processing of an FDRAWCMD ioctl call, which allows local
users to obtain sensitive information from kernel heap
memory by leveraging write access to a /dev/fd device.
(bnc#875798)

Additionally, the following non-security bugs have been fixed :

  - tcp: syncookies: reduce cookie lifetime to 128 seconds
    (bnc#833968).

  - tcp: syncookies: reduce mss table to four values
    (bnc#833968).

  - ia64: Change default PSR.ac from '1' to '0' (Fix erratum
    #237) (bnc#874108).

  - tty: fix up atime/mtime mess, take three (bnc#797175).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=00bbe32fc40478b12864bce2c72e300b
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7573fea8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/797175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/833968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/852553"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/857643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/874108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/875798"
  );
  # https://www.suse.com/support/update/announcement/2014/suse-su-20140772-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2ef7088"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-kdumppae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vmipae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xenpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES10" && (! ereg(pattern:"^4$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-bigsmp-2.6.16.60-0.107.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-debug-2.6.16.60-0.107.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.107.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-kdump-2.6.16.60-0.107.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-kdumppae-2.6.16.60-0.107.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.107.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.107.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.107.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-vmi-2.6.16.60-0.107.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-vmipae-2.6.16.60-0.107.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.107.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"kernel-xenpae-2.6.16.60-0.107.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.107.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-debug-2.6.16.60-0.107.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-default-2.6.16.60-0.107.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-kdump-2.6.16.60-0.107.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-kdumppae-2.6.16.60-0.107.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-smp-2.6.16.60-0.107.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-source-2.6.16.60-0.107.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-syms-2.6.16.60-0.107.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-vmi-2.6.16.60-0.107.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-vmipae-2.6.16.60-0.107.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-xen-2.6.16.60-0.107.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.107.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
