#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:1664 and 
# Oracle Linux Security Advisory ELSA-2016-1664 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(93093);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/07 21:08:17 $");

  script_cve_id("CVE-2016-5696");
  script_osvdb_id(141441);
  script_xref(name:"RHSA", value:"2016:1664");

  script_name(english:"Oracle Linux 6 : kernel (ELSA-2016-1664)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:1664 :

An update for kernel is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

It was found that the RFC 5961 challenge ACK rate limiting as
implemented in the Linux kernel's networking subsystem allowed an
off-path attacker to leak certain information about a given connection
by creating congestion on the global challenge ACK rate limit counter
and then measuring the changes by probing packets. An off-path
attacker could use this flaw to either terminate TCP connection and/or
inject payload into non-secured TCP connection between two endpoints
on the network. (CVE-2016-5696, Important)

Red Hat would like to thank Yue Cao (Cyber Security Group of the CS
department of University of California in Riverside) for reporting
this issue.

Bug Fix(es) :

* When loading the Direct Rendering Manager (DRM) kernel module, the
kernel panicked if DRM was previously unloaded. The kernel panic was
caused by a memory leak of the ID Resolver (IDR2). With this update,
IDR2 is loaded during kernel boot, and the kernel panic no longer
occurs in the described scenario. (BZ#1353827)

* When more than one process attempted to use the 'configfs' directory
entry at the same time, a kernel panic in some cases occurred. With
this update, a race condition between a directory entry and a lookup
operation has been fixed. As a result, the kernel no longer panics in
the described scenario. (BZ#1353828)

* When shutting down the system by running the halt -p command, a
kernel panic occurred due to a conflict between the kernel offlining
CPUs and the sched command, which used the sched group and the sched
domain data without first checking the data. The underlying source
code has been fixed by adding a check to avoid the conflict. As a
result, the described scenario no longer results in a kernel panic.
(BZ#1343894)

* In some cases, running the ipmitool command caused a kernel panic
due to a race condition in the ipmi message handler. This update fixes
the race condition, and the kernel panic no longer occurs in the
described scenario. (BZ#1355980)

* Previously, multiple Very Secure FTP daemon (vsftpd) processes on a
directory with a large number of files led to a high contention rate
on each inode's spinlock, which caused excessive CPU usage. With this
update, a spinlock to protect a single memory-to-memory copy has been
removed from the ext4_getattr() function. As a result, system CPU
usage has been reduced and is no longer excessive in the described
situation. (BZ#1355981)

* When the gfs2_grow utility is used to extend Global File System 2
(GFS2), the next block allocation causes the GFS2 kernel module to
re-read its resource group index. If multiple processes in the GFS2
module raced to do the same thing, one process sometimes overwrote a
valid object pointer with an invalid pointer, which caused either a
kernel panic or a file system corruption. This update ensures that the
resource group object pointer is not overwritten. As a result, neither
kernel panic nor file system corruption occur in the described
scenario. (BZ#1347539)

* Previously, the SCSI Remote Protocol over InfiniBand (IB-SRP) was
disabled due to a bug in the srp_queue() function. As a consequence,
an attempt to enable the Remote Direct Memory Access (RDMA) at boot
caused the kernel to crash. With this update, srp_queue() has been
fixed, and the system now boots as expected when RDMA is enabled.
(BZ#1348062)

Enhancement(s) :

* This update optimizes the efficiency of the Transmission Control
Protocol (TCP) when the peer is using a window under 537 bytes in
size. As a result, devices that use maximum segment size (MSS) of 536
bytes or fewer will experience improved network performance.
(BZ#1354446)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-August/006296.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_exists(release:"EL6", rpm:"kernel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-2.6.32-642.4.2.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-abi-whitelists-2.6.32") && rpm_check(release:"EL6", reference:"kernel-abi-whitelists-2.6.32-642.4.2.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-debug-2.6.32") && rpm_check(release:"EL6", reference:"kernel-debug-2.6.32-642.4.2.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-debug-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-debug-devel-2.6.32-642.4.2.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-devel-2.6.32-642.4.2.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-doc-2.6.32") && rpm_check(release:"EL6", reference:"kernel-doc-2.6.32-642.4.2.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-firmware-2.6.32") && rpm_check(release:"EL6", reference:"kernel-firmware-2.6.32-642.4.2.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-headers-2.6.32") && rpm_check(release:"EL6", reference:"kernel-headers-2.6.32-642.4.2.el6")) flag++;
if (rpm_check(release:"EL6", reference:"perf-2.6.32-642.4.2.el6")) flag++;
if (rpm_check(release:"EL6", reference:"python-perf-2.6.32-642.4.2.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
