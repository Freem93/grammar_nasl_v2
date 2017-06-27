#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0907. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63960);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/13 15:17:27 $");

  script_cve_id("CVE-2010-2521");
  script_bugtraq_id(42249);
  script_osvdb_id(67243);
  script_xref(name:"RHSA", value:"2010:0907");

  script_name(english:"RHEL 5 : kernel (RHSA-2010:0907)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix one security issue and four bugs are
now available for Red Hat Enterprise Linux 5.4 Extended Update
Support.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issue :

* Buffer overflow flaws were found in the Linux kernel's
implementation of the server-side External Data Representation (XDR)
for the Network File System (NFS) version 4. An attacker on the local
network could send a specially crafted large compound request to the
NFSv4 server, which could possibly result in a kernel panic (denial of
service) or, potentially, code execution. (CVE-2010-2521, Important)

This update also fixes the following bugs :

* A race condition existed when generating new process IDs with the
result that the wrong process could have been signaled or killed
accidentally, leading to various application faults. This update
detects and disallows the reuse of PID numbers. (BZ#638865)

* In a two node cluster, moving 100 files between two folders using
the lock master was nearly instantaneous. However, not using the lock
master resulted in considerably worse performance on both GFS1 (Global
File System 1) and GFS2 (Global File System 2) file systems. With this
update, not using the lock master does not lead to worsened
performance on either of the aforementioned file systems. (BZ#639071)

* The device naming changed after additional devices were added to the
system and caused various problems. With this update, device naming
remains constant after adding any additional devices. (BZ#646764)

* On some bnx2-based devices, frames could drop unexpectedly. This was
shown by the increasing 'rx_fw_discards' values in the 'ethtool
--statistics' output. With this update, frames are no longer dropped
and all bnx2-based devices work as expected. (BZ#649254)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-2521.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0907.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/23");
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
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-2.6.18-164.30.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-2.6.18-164.30.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-2.6.18-164.30.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-PAE-2.6.18-164.30.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-PAE-devel-2.6.18-164.30.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-debug-2.6.18-164.30.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-debug-2.6.18-164.30.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-debug-2.6.18-164.30.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-debug-devel-2.6.18-164.30.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-debug-devel-2.6.18-164.30.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-debug-devel-2.6.18-164.30.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-devel-2.6.18-164.30.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-devel-2.6.18-164.30.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-devel-2.6.18-164.30.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", reference:"kernel-doc-2.6.18-164.30.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i386", reference:"kernel-headers-2.6.18-164.30.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-headers-2.6.18-164.30.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-headers-2.6.18-164.30.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-kdump-2.6.18-164.30.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-kdump-devel-2.6.18-164.30.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-xen-2.6.18-164.30.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-xen-2.6.18-164.30.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-xen-devel-2.6.18-164.30.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-xen-devel-2.6.18-164.30.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
