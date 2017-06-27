#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0927 and 
# CentOS Errata and Security Advisory 2014:0927 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(76839);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/04/28 18:05:38 $");

  script_cve_id("CVE-2013-4148", "CVE-2013-4149", "CVE-2013-4150", "CVE-2013-4151", "CVE-2013-4527", "CVE-2013-4529", "CVE-2013-4535", "CVE-2013-4536", "CVE-2013-4541", "CVE-2013-4542", "CVE-2013-6399", "CVE-2014-0182", "CVE-2014-0222", "CVE-2014-0223", "CVE-2014-3461");
  script_osvdb_id(106046, 106067, 106983);
  script_xref(name:"RHSA", value:"2014:0927");

  script_name(english:"CentOS 7 : qemu-kvm (CESA-2014:0927)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated qemu-kvm packages that fix multiple security issues and
various bugs are now available for Red Hat Enterprise Linux 7.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. The qemu-kvm package provides
the user-space component for running virtual machines using KVM.

Two integer overflow flaws were found in the QEMU block driver for
QCOW version 1 disk images. A user able to alter the QEMU disk image
files loaded by a guest could use either of these flaws to corrupt
QEMU process memory on the host, which could potentially result in
arbitrary code execution on the host with the privileges of the QEMU
process. (CVE-2014-0222, CVE-2014-0223)

Multiple buffer overflow, input validation, and out-of-bounds write
flaws were found in the way virtio, virtio-net, virtio-scsi, usb, and
hpet drivers of QEMU handled state loading after migration. A user
able to alter the savevm data (either on the disk or over the wire
during migration) could use either of these flaws to corrupt QEMU
process memory on the (destination) host, which could potentially
result in arbitrary code execution on the host with the privileges of
the QEMU process. (CVE-2013-4148, CVE-2013-4149, CVE-2013-4150,
CVE-2013-4151, CVE-2013-4527, CVE-2013-4529, CVE-2013-4535,
CVE-2013-4536, CVE-2013-4541, CVE-2013-4542, CVE-2013-6399,
CVE-2014-0182, CVE-2014-3461)

These issues were discovered by Michael S. Tsirkin, Anthony Liguori
and Michael Roth of Red Hat: CVE-2013-4148, CVE-2013-4149,
CVE-2013-4150, CVE-2013-4151, CVE-2013-4527, CVE-2013-4529,
CVE-2013-4535, CVE-2013-4536, CVE-2013-4541, CVE-2013-4542,
CVE-2013-6399, CVE-2014-0182, and CVE-2014-3461.

This update also fixes the following bugs :

* Previously, QEMU did not free pre-allocated zero clusters correctly
and the clusters under some circumstances leaked. With this update,
pre-allocated zero clusters are freed appropriately and the cluster
leaks no longer occur. (BZ#1110188)

* Prior to this update, the QEMU command interface did not properly
handle resizing of cache memory during guest migration, causing QEMU
to terminate unexpectedly with a segmentation fault and QEMU to fail.
This update fixes the related code and QEMU no longer crashes in the
described situation. (BZ#1110191)

* Previously, when a guest device was hot unplugged, QEMU correctly
removed the corresponding file descriptor watch but did not re-create
it after the device was re-connected. As a consequence, the guest
became unable to receive any data from the host over this device. With
this update, the file descriptor's watch is re-created and the guest
in the above scenario can communicate with the host as expected.
(BZ#1110219)

* Previously, the QEMU migration code did not account for the gaps
caused by hot unplugged devices and thus expected more memory to be
transferred during migrations. As a consequence, guest migration
failed to complete after multiple devices were hot unplugged. In
addition, the migration info text displayed erroneous values for the
'remaining ram' item. With this update, QEMU calculates memory after a
device has been unplugged correctly, and any subsequent guest
migrations proceed as expected. (BZ#1110189)

All qemu-kvm users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing this update, shut down all running virtual machines. Once
all virtual machines have shut down, start them again for this update
to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-July/020447.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?da8a2773"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qemu-kvm packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libcacard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libcacard-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libcacard-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/26");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libcacard-1.5.3-60.el7_0.5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libcacard-devel-1.5.3-60.el7_0.5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libcacard-tools-1.5.3-60.el7_0.5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qemu-guest-agent-1.5.3-60.el7_0.5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qemu-img-1.5.3-60.el7_0.5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qemu-kvm-1.5.3-60.el7_0.5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qemu-kvm-common-1.5.3-60.el7_0.5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"qemu-kvm-tools-1.5.3-60.el7_0.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
