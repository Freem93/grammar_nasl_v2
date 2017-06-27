#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0670. The text 
# itself is copyright (C) Red Hat, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63951);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/05/02 18:01:07 $");

  script_cve_id("CVE-2010-2240", "CVE-2010-2798");
  script_xref(name:"RHSA", value:"2010:0670");

  script_name(english:"RHEL 5 : kernel (RHSA-2010:0670)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix two security issues and three bugs
are now available for Red Hat Enterprise Linux 5.4 Extended Update
Support.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* When an application has a stack overflow, the stack could silently
overwrite another memory mapped area instead of a segmentation fault
occurring, which could cause an application to execute arbitrary code,
possibly leading to privilege escalation. It is known that the X
Window System server can be used to trigger this flaw. (CVE-2010-2240,
Important)

* A miscalculation of the size of the free space of the initial
directory entry in a directory leaf block was found in the Linux
kernel Global File System 2 (GFS2) implementation. A local,
unprivileged user with write access to a GFS2-mounted file system
could perform a rename operation on that file system to trigger a NULL
pointer dereference, possibly resulting in a denial of service or
privilege escalation. (CVE-2010-2798, Important)

Red Hat would like to thank the X.Org security team for reporting
CVE-2010-2240, with upstream acknowledging Rafal Wojtczuk as the
original reporter; and Grant Diffey of CenITex for reporting
CVE-2010-2798.

This update also fixes the following bugs :

* Problems receiving network traffic correctly via a non-standard
layer 3 protocol when using the ixgbe driver. This update corrects
this issue. (BZ#618275)

* A bug was found in the way the megaraid_sas driver (for SAS based
RAID controllers) handled physical disks and management IOCTLs. All
physical disks were exported to the disk layer, allowing an oops in
megasas_complete_cmd_dpc() when completing the IOCTL command if a
timeout occurred. One possible trigger for this bug was running
'mkfs'. This update resolves this issue by updating the megaraid_sas
driver to version 4.31. (BZ#619363)

* Previously, Message Signaled Interrupts (MSI) resulted in PCI bus
writes to mask and unmask the MSI IRQ for a PCI device. These
unnecessary PCI bus writes resulted in the serialization of MSIs,
leading to poor performance on systems with high MSI load. This update
adds a new kernel boot parameter, msi_nolock, which forgoes the PCI
bus writes and allows for better simultaneous processing of MSIs.
(BZ#621939)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-2240.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-2798.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0670.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-2.6.18-164.25.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-2.6.18-164.25.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-2.6.18-164.25.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-PAE-2.6.18-164.25.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-PAE-devel-2.6.18-164.25.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-debug-2.6.18-164.25.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-debug-2.6.18-164.25.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-debug-2.6.18-164.25.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-debug-devel-2.6.18-164.25.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-debug-devel-2.6.18-164.25.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-debug-devel-2.6.18-164.25.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-devel-2.6.18-164.25.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-devel-2.6.18-164.25.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-devel-2.6.18-164.25.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", reference:"kernel-doc-2.6.18-164.25.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i386", reference:"kernel-headers-2.6.18-164.25.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-headers-2.6.18-164.25.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-headers-2.6.18-164.25.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-kdump-2.6.18-164.25.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-kdump-devel-2.6.18-164.25.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-xen-2.6.18-164.25.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-xen-2.6.18-164.25.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-xen-devel-2.6.18-164.25.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-xen-devel-2.6.18-164.25.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
