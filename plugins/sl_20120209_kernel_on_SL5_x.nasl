#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61241);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/09/06 20:39:15 $");

  script_cve_id("CVE-2011-3638", "CVE-2011-4086", "CVE-2011-4127", "CVE-2012-0028", "CVE-2012-0207");

  script_name(english:"Scientific Linux Security Update : kernel on SL5.x i386/x86_64");
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
"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

  - Using the SG_IO ioctl to issue SCSI requests to
    partitions or LVM volumes resulted in the requests being
    passed to the underlying block device. If a privileged
    user only had access to a single partition or LVM
    volume, they could use this flaw to bypass those
    restrictions and gain read and write access (and be able
    to issue other SCSI commands) to the entire block
    device. (CVE-2011-4127, Important)

  - A flaw was found in the way the Linux kernel handled
    robust list pointers of user-space held futexes across
    exec() calls. A local, unprivileged user could use this
    flaw to cause a denial of service or, eventually,
    escalate their privileges. (CVE-2012-0028, Important)

  - A flaw was found in the Linux kernel in the way
    splitting two extents in
    ext4_ext_convert_to_initialized() worked. A local,
    unprivileged user with the ability to mount and unmount
    ext4 file systems could use this flaw to cause a denial
    of service. (CVE-2011-3638, Moderate)

  - A flaw was found in the way the Linux kernel's
    journal_unmap_buffer() function handled buffer head
    states. On systems that have an ext4 file system with a
    journal mounted, a local, unprivileged user could use
    this flaw to cause a denial of service. (CVE-2011-4086,
    Moderate)

  - A divide-by-zero flaw was found in the Linux kernel's
    igmp_heard_query() function. An attacker able to send
    certain IGMP (Internet Group Management Protocol)
    packets to a target system could use this flaw to cause
    a denial of service. (CVE-2012-0207, Moderate)

This update also fixes the following bugs :

  - When a host was in recovery mode and a SCSI scan
    operation was initiated, the scan operation failed and
    provided no error output. This bug has been fixed and
    the SCSI layer now waits for recovery of the host to
    complete scan operations for devices.

  - SG_IO ioctls were not implemented correctly in the
    previous virtio-blk driver. Sending an SG_IO ioctl
    request to a virtio-blk disk caused the sending thread
    to enter an uninterruptible sleep state ('D' state).
    With this update, SG_IO ioctls are rejected by the
    virtio-blk driver: the ioctl system call will simply
    return an ENOTTY ('Inappropriate ioctl for device')
    error and the thread will continue normally.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1202&L=scientific-linux-errata&T=0&P=1858
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75e6c708"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-274.18.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-274.18.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-274.18.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-274.18.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-274.18.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-debuginfo-2.6.18-274.18.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-274.18.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-2.6.18-274.18.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-common-2.6.18-274.18.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-274.18.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-274.18.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-274.18.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-274.18.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-debuginfo-2.6.18-274.18.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-274.18.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
