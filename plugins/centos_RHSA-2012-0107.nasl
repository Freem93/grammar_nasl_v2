#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0107 and 
# CentOS Errata and Security Advisory 2012:0107 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(57922);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/06/28 23:58:54 $");

  script_cve_id("CVE-2011-3638", "CVE-2011-4086", "CVE-2011-4127", "CVE-2012-0028", "CVE-2012-0207");
  script_bugtraq_id(50322, 51176, 51343);
  script_osvdb_id(76666, 78014, 78225, 79097, 79098);
  script_xref(name:"RHSA", value:"2012:0107");

  script_name(english:"CentOS 5 : kernel (CESA-2012:0107)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and two bugs
are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* Using the SG_IO ioctl to issue SCSI requests to partitions or LVM
volumes resulted in the requests being passed to the underlying block
device. If a privileged user only had access to a single partition or
LVM volume, they could use this flaw to bypass those restrictions and
gain read and write access (and be able to issue other SCSI commands)
to the entire block device. Refer to Red Hat Knowledgebase article
DOC-67874, linked to in the References, for further details about this
issue. (CVE-2011-4127, Important)

* A flaw was found in the way the Linux kernel handled robust list
pointers of user-space held futexes across exec() calls. A local,
unprivileged user could use this flaw to cause a denial of service or,
eventually, escalate their privileges. (CVE-2012-0028, Important)

* A flaw was found in the Linux kernel in the way splitting two
extents in ext4_ext_convert_to_initialized() worked. A local,
unprivileged user with the ability to mount and unmount ext4 file
systems could use this flaw to cause a denial of service.
(CVE-2011-3638, Moderate)

* A flaw was found in the way the Linux kernel's
journal_unmap_buffer() function handled buffer head states. On systems
that have an ext4 file system with a journal mounted, a local,
unprivileged user could use this flaw to cause a denial of service.
(CVE-2011-4086, Moderate)

* A divide-by-zero flaw was found in the Linux kernel's
igmp_heard_query() function. An attacker able to send certain IGMP
(Internet Group Management Protocol) packets to a target system could
use this flaw to cause a denial of service. (CVE-2012-0207, Moderate)

Red Hat would like to thank Zheng Liu for reporting CVE-2011-3638, and
Simon McVittie for reporting CVE-2012-0207.

This update also fixes the following bugs :

* When a host was in recovery mode and a SCSI scan operation was
initiated, the scan operation failed and provided no error output.
This bug has been fixed and the SCSI layer now waits for recovery of
the host to complete scan operations for devices. (BZ#772162)

* SG_IO ioctls were not implemented correctly in the Red Hat
Enterprise Linux 5 virtio-blk driver. Sending an SG_IO ioctl request
to a virtio-blk disk caused the sending thread to enter an
uninterruptible sleep state ('D' state). With this update, SG_IO
ioctls are rejected by the virtio-blk driver: the ioctl system call
will simply return an ENOTTY ('Inappropriate ioctl for device') error
and the thread will continue normally. (BZ#773322)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-February/018426.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?decb0334"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-274.18.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-274.18.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-274.18.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-274.18.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-274.18.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-274.18.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-274.18.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-274.18.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-274.18.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-274.18.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
