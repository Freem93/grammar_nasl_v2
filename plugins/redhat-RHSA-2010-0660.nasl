#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0660. The text 
# itself is copyright (C) Red Hat, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63950);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/13 15:17:26 $");

  script_cve_id("CVE-2010-2240", "CVE-2010-2798");
  script_bugtraq_id(42124);
  script_xref(name:"RHSA", value:"2010:0660");

  script_name(english:"RHEL 5 : kernel (RHSA-2010:0660)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix two security issues and multiple bugs
are now available for Red Hat Enterprise Linux 5.3 Extended Update
Support.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* when an application has a stack overflow, the stack could silently
overwrite another memory mapped area instead of a segmentation fault
occurring, which could cause an application to execute arbitrary code,
possibly leading to privilege escalation. It is known that the X
Window System server can be used to trigger this flaw. (CVE-2010-2240,
Important)

* a miscalculation of the size of the free space of the initial
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

* the Red Hat Enterprise Linux 5.3 General Availability (GA) release
introduced a regression in iSCSI failover time. While there was heavy
I/O on the iSCSI layer, attempting to log out of an iSCSI connection
at the same time a network problem was occurring, such as a switch
dying or a cable being pulled out, resulted in iSCSI failover taking
several minutes. With this update, failover occurs as expected.
(BZ#583898)

* a bug was found in the way the megaraid_sas driver (for SAS based
RAID controllers) handled physical disks and management IOCTLs. All
physical disks were exported to the disk layer, allowing an oops in
megasas_complete_cmd_dpc() when completing the IOCTL command if a
timeout occurred. One possible trigger for this bug was running
'mkfs'. This update resolves this issue by updating the megaraid_sas
driver to version 4.31. (BZ#619362)

* this update upgrades the bnx2x driver to version 1.52.1-6, and the
bnx2x firmware to version 1.52.1-6, incorporating multiple bug fixes
and enhancements. These fixes include: A race condition on systems
using the bnx2x driver due to multiqueue being used to transmit data,
but only a single queue transmit ON/OFF scheme being used (only a
single queue is used with this update); a bug that could have led to a
kernel panic when using iSCSI offload; and a bug that caused a
firmware crash, causing network devices using the bnx2x driver to lose
network connectivity. When this firmware crash occurred, errors such
as 'timeout polling for state' and 'Stop leading failed!' were logged.
A system reboot was required to restore network connectivity.
(BZ#620663, BZ#620668, BZ#620669, BZ#620665)

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
    value:"http://rhn.redhat.com/errata/RHSA-2010-0660.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-2.6.18-128.23.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-2.6.18-128.23.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-2.6.18-128.23.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-PAE-2.6.18-128.23.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-PAE-devel-2.6.18-128.23.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-debug-2.6.18-128.23.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-debug-2.6.18-128.23.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-debug-2.6.18-128.23.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-debug-devel-2.6.18-128.23.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-debug-devel-2.6.18-128.23.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-debug-devel-2.6.18-128.23.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-devel-2.6.18-128.23.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-devel-2.6.18-128.23.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-devel-2.6.18-128.23.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", reference:"kernel-doc-2.6.18-128.23.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"kernel-headers-2.6.18-128.23.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-headers-2.6.18-128.23.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-headers-2.6.18-128.23.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-kdump-2.6.18-128.23.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-kdump-devel-2.6.18-128.23.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-xen-2.6.18-128.23.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-xen-2.6.18-128.23.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-xen-devel-2.6.18-128.23.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-xen-devel-2.6.18-128.23.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
