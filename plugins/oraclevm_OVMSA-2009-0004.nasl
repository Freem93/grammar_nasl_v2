#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2009-0004.
#

include("compat.inc");

if (description)
{
  script_id(79453);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2008-3528", "CVE-2008-5700", "CVE-2009-0028", "CVE-2009-0269", "CVE-2009-0322", "CVE-2009-0675", "CVE-2009-0676", "CVE-2009-0778");
  script_bugtraq_id(33846);
  script_osvdb_id(52204);

  script_name(english:"OracleVM 2.1 : kernel (OVMSA-2009-0004)");
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

CVE-2008-3528 The error-reporting functionality in (1) fs/ext2/dir.c,
(2) fs/ext3/dir.c, and possibly (3) fs/ext4/dir.c in the Linux kernel
2.6.26.5 does not limit the number of printk console messages that
report directory corruption, which allows physically proximate
attackers to cause a denial of service (temporary system hang) by
mounting a filesystem that has corrupted dir->i_size and dir->i_blocks
values and performing (a) read or (b) write operations. NOTE: there
are limited scenarios in which this crosses privilege boundaries.

CVE-2008-5700 libata in the Linux kernel before 2.6.27.9 does not set
minimum timeouts for SG_IO requests, which allows local users to cause
a denial of service (Programmed I/O mode on drives) via multiple
simultaneous invocations of an unspecified test program.

CVE-2009-0028 The clone system call in the Linux kernel 2.6.28 and
earlier allows local users to send arbitrary signals to a parent
process from an unprivileged child process by launching an additional
child process with the CLONE_PARENT flag, and then letting this new
process exit. CVE-2009-0322 drivers/firmware/dell_rbu.c in the Linux
kernel before 2.6.27.13, and 2.6.28.x before 2.6.28.2, allows local
users to cause a denial of service (system crash) via a read system
call that specifies zero bytes from the (1) image_type or (2)
packet_size file in /sys/devices/platform/dell_rbu/. CVE-2009-0675 The
skfp_ioctl function in drivers/net/skfp/skfddi.c in the Linux kernel
before 2.6.28.6 permits SKFP_CLR_STATS requests only when the
CAP_NET_ADMIN capability is absent, instead of when this capability is
present, which allows local users to reset the driver statistics,
related to an 'inverted logic' issue. CVE-2009-0676 The
sock_getsockopt function in net/core/sock.c in the Linux kernel before
2.6.28.6 does not initialize a certain structure member, which allows
local users to obtain potentially sensitive information from kernel
memory via an SO_BSDCOMPAT getsockopt request.

  - CVE-2008-3528 - [fs] ext[234]: directory corruption DoS
    (Eugene Teo) 

  - CVE-2008-5700 - [block] enforce a minimum SG_IO timeout
    (Eugene Teo) 

  - CVE-2009-0322 - [firmware] dell_rbu: prevent oops (Don
    Howard) 

  - CVE-2009-0028 - [misc] minor signal handling
    vulnerability (Oleg Nesterov) [479963 479964]

  - CVE-2009-0676 - [net] memory disclosure in SO_BSDCOMPAT
    gsopt (Eugene Teo) [486517 486518]

  - CVE-2009-0675 - [net] skfp_ioctl inverted logic flaw
    (Eugene Teo) 

  - CVE-2009-0778 - not required

  - CVE-2009-0269 - not required

  - Enable enic

  - Finish porting infrastructure for fnic but disable it on
    32bit

  - Add netconsole support for bonding in dom0 (Tina Yang)
    [orabug 8231228]

  - Add Cisco fnic/enic support, requires fc infrastructure
    from el5u3"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2009-April/000017.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a2723e7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-BOOT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-BOOT-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-ovs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-ovs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/16");
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
if (rpm_check(release:"OVS2.1", reference:"kernel-BOOT-2.6.18-8.1.15.1.30.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"kernel-BOOT-devel-2.6.18-8.1.15.1.30.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"kernel-kdump-2.6.18-8.1.15.1.30.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"kernel-kdump-devel-2.6.18-8.1.15.1.30.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"kernel-ovs-2.6.18-8.1.15.1.30.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"kernel-ovs-devel-2.6.18-8.1.15.1.30.el5")) flag++;

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
