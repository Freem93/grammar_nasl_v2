#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1997. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80072);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/06 15:51:00 $");

  script_cve_id("CVE-2012-6657", "CVE-2014-3673", "CVE-2014-3687", "CVE-2014-3688", "CVE-2014-5471", "CVE-2014-5472", "CVE-2014-6410", "CVE-2014-9322");
  script_bugtraq_id(69396, 69428, 69799, 69803, 70766, 70768, 70883, 71685);
  script_osvdb_id(110564, 110565, 111430, 113724, 113726, 113727, 115919);
  script_xref(name:"RHSA", value:"2014:1997");

  script_name(english:"RHEL 6 : kernel (RHSA-2014:1997)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
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
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-6657.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3673.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3687.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3688.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-5471.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-5472.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6410.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-9322.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-1997.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:1997";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"kernel-abi-whitelists-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-devel-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-devel-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debuginfo-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debuginfo-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-devel-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-devel-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-devel-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"kernel-doc-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"kernel-firmware-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-headers-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-headers-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-headers-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-devel-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"perf-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perf-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perf-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"perf-debuginfo-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perf-debuginfo-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perf-debuginfo-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-perf-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-perf-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-perf-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-perf-debuginfo-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-perf-debuginfo-2.6.32-504.3.3.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-perf-debuginfo-2.6.32-504.3.3.el6")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / etc");
  }
}
