#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(93096);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/19 14:25:14 $");

  script_cve_id("CVE-2016-5696");

  script_name(english:"Scientific Linux Security Update : kernel on SL6.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security Fix(es) :

It was found that the RFC 5961 challenge ACK rate limiting as
implemented in the Linux kernel's networking subsystem allowed an
off-path attacker to leak certain information about a given connection
by creating congestion on the global challenge ACK rate limit counter
and then measuring the changes by probing packets. An off-path
attacker could use this flaw to either terminate TCP connection and/or
inject payload into non-secured TCP connection between two endpoints
on the network. (CVE-2016-5696, Important)

Bug Fix(es) :

  - When loading the Direct Rendering Manager (DRM) kernel
    module, the kernel panicked if DRM was previously
    unloaded. The kernel panic was caused by a memory leak
    of the ID Resolver (IDR2). With this update, IDR2 is
    loaded during kernel boot, and the kernel panic no
    longer occurs in the described scenario.

  - When more than one process attempted to use the
    'configfs' directory entry at the same time, a kernel
    panic in some cases occurred. With this update, a race
    condition between a directory entry and a lookup
    operation has been fixed. As a result, the kernel no
    longer panics in the described scenario.

  - When shutting down the system by running the halt -p
    command, a kernel panic occurred due to a conflict
    between the kernel offlining CPUs and the sched command,
    which used the sched group and the sched domain data
    without first checking the data. The underlying source
    code has been fixed by adding a check to avoid the
    conflict. As a result, the described scenario no longer
    results in a kernel panic.

  - In some cases, running the ipmitool command caused a
    kernel panic due to a race condition in the ipmi message
    handler. This update fixes the race condition, and the
    kernel panic no longer occurs in the described scenario.

  - Previously, multiple Very Secure FTP daemon (vsftpd)
    processes on a directory with a large number of files
    led to a high contention rate on each inode's spinlock,
    which caused excessive CPU usage. With this update, a
    spinlock to protect a single memory-to-memory copy has
    been removed from the ext4_getattr() function. As a
    result, system CPU usage has been reduced and is no
    longer excessive in the described situation.

  - When the gfs2_grow utility is used to extend Global File
    System 2 (GFS2), the next block allocation causes the
    GFS2 kernel module to re-read its resource group index.
    If multiple processes in the GFS2 module raced to do the
    same thing, one process sometimes overwrote a valid
    object pointer with an invalid pointer, which caused
    either a kernel panic or a file system corruption. This
    update ensures that the resource group object pointer is
    not overwritten. As a result, neither kernel panic nor
    file system corruption occur in the described scenario.

  - Previously, the SCSI Remote Protocol over InfiniBand
    (IB-SRP) was disabled due to a bug in the srp_queue()
    function. As a consequence, an attempt to enable the
    Remote Direct Memory Access (RDMA) at boot caused the
    kernel to crash. With this update, srp_queue() has been
    fixed, and the system now boots as expected when RDMA is
    enabled.

Enhancement(s) :

  - This update optimizes the efficiency of the Transmission
    Control Protocol (TCP) when the peer is using a window
    under 537 bytes in size. As a result, devices that use
    maximum segment size (MSS) of 536 bytes or fewer will
    experience improved network performance."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1608&L=scientific-linux-errata&F=&S=&P=13982
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c2a7b67"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-642.4.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-abi-whitelists-2.6.32-642.4.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-642.4.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-642.4.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-642.4.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-642.4.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-common-i686-2.6.32-642.4.2.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-642.4.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-642.4.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-642.4.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-642.4.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-642.4.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-642.4.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-642.4.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-642.4.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-642.4.2.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
