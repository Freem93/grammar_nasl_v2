#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1997 and 
# CentOS Errata and Security Advisory 2014:1997 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(80088);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 18:05:38 $");

  script_cve_id("CVE-2012-6657", "CVE-2014-3673", "CVE-2014-3687", "CVE-2014-3688", "CVE-2014-5471", "CVE-2014-5472", "CVE-2014-6410", "CVE-2014-9322");
  script_bugtraq_id(69396, 69428, 69799, 69803, 70766, 70768, 70883, 71685);
  script_osvdb_id(110564, 110565, 111430, 113724, 113726, 113727, 115919);
  script_xref(name:"RHSA", value:"2014:1997");

  script_name(english:"CentOS 6 : kernel (CESA-2014:1997)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* A flaw was found in the way the Linux kernel handled GS segment
register base switching when recovering from a #SS (stack segment)
fault on an erroneous return to user space. A local, unprivileged user
could use this flaw to escalate their privileges on the system.
(CVE-2014-9322, Important)

* A flaw was found in the way the Linux kernel's SCTP implementation
handled malformed or duplicate Address Configuration Change Chunks
(ASCONF). A remote attacker could use either of these flaws to crash
the system. (CVE-2014-3673, CVE-2014-3687, Important)

* A flaw was found in the way the Linux kernel's SCTP implementation
handled the association's output queue. A remote attacker could send
specially crafted packets that would cause the system to use an
excessive amount of memory, leading to a denial of service.
(CVE-2014-3688, Important)

* A stack overflow flaw caused by infinite recursion was found in the
way the Linux kernel's UDF file system implementation processed
indirect ICBs. An attacker with physical access to the system could
use a specially crafted UDF image to crash the system. (CVE-2014-6410,
Low)

* It was found that the Linux kernel's networking implementation did
not correctly handle the setting of the keepalive socket option on raw
sockets. A local user able to create a raw socket could use this flaw
to crash the system. (CVE-2012-6657, Low)

* It was found that the parse_rock_ridge_inode_internal() function of
the Linux kernel's ISOFS implementation did not correctly check
relocated directories when processing Rock Ridge child link (CL) tags.
An attacker with physical access to the system could use a specially
crafted ISO image to crash the system or, potentially, escalate their
privileges on the system. (CVE-2014-5471, CVE-2014-5472, Low)

Red Hat would like to thank Andy Lutomirski for reporting
CVE-2014-9322. The CVE-2014-3673 issue was discovered by Liu Wei of
Red Hat.

Bug fixes :

* This update fixes a race condition issue between the
sock_queue_err_skb function and sk_forward_alloc handling in the
socket error queue (MSG_ERRQUEUE), which could occasionally cause the
kernel, for example when using PTP, to incorrectly track allocated
memory for the error queue, in which case a traceback would occur in
the system log. (BZ#1155427)

* The zcrypt device driver did not detect certain crypto cards and the
related domains for crypto adapters on System z and s390x
architectures. Consequently, it was not possible to run the system on
new crypto hardware. This update enables toleration mode for such
devices so that the system can make use of newer crypto hardware.
(BZ#1158311)

* After mounting and unmounting an XFS file system several times
consecutively, the umount command occasionally became unresponsive.
This was caused by the xlog_cil_force_lsn() function that was not
waiting for completion as expected. With this update,
xlog_cil_force_lsn() has been modified to correctly wait for
completion, thus fixing this bug. (BZ#1158325)

* When using the ixgbe adapter with disabled LRO and the tx-usec or
rs-usec variables set to 0, transmit interrupts could not be set lower
than the default of 8 buffered tx frames. Consequently, a delay of TCP
transfer occurred. The restriction of a minimum of 8 buffered frames
has been removed, and the TCP delay no longer occurs. (BZ#1158326)

* The offb driver has been updated for the QEMU standard VGA adapter,
fixing an incorrect displaying of colors issue. (BZ#1158328)

* Under certain circumstances, when a discovered MTU expired, the IPv6
connection became unavailable for a short period of time. This bug has
been fixed, and the connection now works as expected. (BZ#1161418)

* A low throughput occurred when using the dm-thin driver to write to
unprovisioned or shared chunks for a thin pool with the chunk size
bigger than the max_sectors_kb variable. (BZ#1161420)

* Large write workloads on thin LVs could cause the iozone and
smallfile utilities to terminate unexpectedly. (BZ#1161421)"
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-December/020838.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e23ca55d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"kernel-2.6.32-504.3.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-abi-whitelists-2.6.32-504.3.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-2.6.32-504.3.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-devel-2.6.32-504.3.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-devel-2.6.32-504.3.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-doc-2.6.32-504.3.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-firmware-2.6.32-504.3.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-headers-2.6.32-504.3.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"perf-2.6.32-504.3.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-perf-2.6.32-504.3.3.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
