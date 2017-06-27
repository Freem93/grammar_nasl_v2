#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0307 and 
# CentOS Errata and Security Advisory 2017:0307 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(97389);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/02/27 15:13:34 $");

  script_cve_id("CVE-2016-6136", "CVE-2016-9555");
  script_osvdb_id(140971, 147698);
  script_xref(name:"RHSA", value:"2017:0307");

  script_name(english:"CentOS 6 : kernel (CESA-2017:0307)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* When creating audit records for parameters to executed children
processes, an attacker can convince the Linux kernel audit subsystem
can create corrupt records which may allow an attacker to misrepresent
or evade logging of executing commands. (CVE-2016-6136, Moderate)

* A flaw was found in the Linux kernel's implementation of the SCTP
protocol. A remote attacker could trigger an out-of-bounds read with
an offset of up to 64kB potentially causing the system to crash.
(CVE-2016-9555, Moderate)

Bug Fix(es) :

* The qlnic driver previously attempted to fetch pending transmission
descriptors before all writes were complete, which lead to firmware
hangs. With this update, the qlcnic driver has been fixed to complete
all writes before the hardware fetches any pending transmission
descriptors. As a result, the firmware no longer hangs with the qlcnic
driver. (BZ#1403143)

* Previously, when a NFS share was mounted, the file-system (FS) cache
was incorrectly enabled even when the '-o fsc' option was not used in
the mount command. Consequently, the cachefilesd service stored files
in the NFS share even when not instructed to by the user. With this
update, NFS does not use the FS cache if not instructed by the '-o
fsc' option. As a result, NFS no longer enables caching if the '-o
fsc' option is not used. (BZ#1399172)

* Previously, an NFS client and NFS server got into a NFS4 protocol
loop involving a WRITE action and a NFS4ERR_EXPIRED response when the
current_fileid counter got to the wraparound point by overflowing the
value of 32 bits. This update fixes the NFS server to handle the
current_fileid wraparound. As a result, the described NFS4 protocol
loop no longer occurs. (BZ#1399174)

* Previously, certain configurations of the Hewlett Packard Smart
Array (HPSA) devices caused hardware to be set offline incorrectly
when the HPSA driver was expected to wait for existing I/O operations
to complete. Consequently, a kernel panic occurred. This update
prevents the described problem. As a result, the kernel panic no
longer occurs. (BZ#1399175)

* Previously, memory corruption by copying data into the wrong memory
locations sometimes occurred, because the __copy_tofrom_user()
function was returning incorrect values. This update fixes the
__copy_tofrom_user() function so that it no longer returns larger
values than the number of bytes it was asked to copy. As a result,
memory corruption no longer occurs in he described scenario.
(BZ#1398185)

* Previously, guest virtual machines (VMs) on a Hyper-V server cluster
got in some cases rebooted during the graceful node failover test,
because the host kept sending heartbeat packets independently of
guests responding to them. This update fixes the bug by properly
responding to all the heartbeat messages in the queue, even if they
are pending. As a result, guest VMs no longer get rebooted under the
described circumstances. (BZ#1397739)

* When the 'punching hole' feature of the fallocate utility was used
on an ext4 file system inode with extent depth of 1, the extent tree
of the inode sometimes became corrupted. With this update, the
underlying source code has been fixed, and extent tree corruption no
longer occurs in the described situation. (BZ#1397808)"
  );
  # http://lists.centos.org/pipermail/centos-announce/2017-February/022281.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f25f79f7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"kernel-2.6.32-642.15.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-abi-whitelists-2.6.32-642.15.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-2.6.32-642.15.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-devel-2.6.32-642.15.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-devel-2.6.32-642.15.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-doc-2.6.32-642.15.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-firmware-2.6.32-642.15.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-headers-2.6.32-642.15.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"perf-2.6.32-642.15.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-perf-2.6.32-642.15.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
