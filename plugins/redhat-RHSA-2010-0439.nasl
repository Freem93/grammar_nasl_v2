#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0439. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63934);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/05/02 17:31:16 $");

  script_cve_id("CVE-2010-1188");
  script_bugtraq_id(39016);
  script_xref(name:"RHSA", value:"2010:0439");

  script_name(english:"RHEL 5 : kernel (RHSA-2010:0439)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix one security issue and two bugs are
now available for Red Hat Enterprise Linux 5.3 Extended Update
Support.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issue :

* a use-after-free flaw was found in the tcp_rcv_state_process()
function in the Linux kernel TCP/IP protocol suite implementation. If
a system using IPv6 had the IPV6_RECVPKTINFO option set on a listening
socket, a remote attacker could send an IPv6 packet to that system,
causing a kernel panic (denial of service). (CVE-2010-1188, Important)

This update also fixes the following bugs :

* a memory leak occurred when reading files on an NFS file system that
was mounted with the 'noac' option, causing memory to slowly be
consumed. Unmounting the file system did not free the memory. With
this update, the memory is correctly freed, which resolves this issue.
(BZ#588221)

* the RHSA-2009:0225 update fixed a bug where, in some cases, on
systems with the kdump service enabled, pressing Alt+SysRq+C to
trigger a crash resulted in a system hang; therefore, the system did
not restart and boot the dump-capture kernel as expected; no vmcore
file was logged; and the following message was displayed on the
console :

BUG: warning at arch/[arch]/kernel/crash.c:[xxx]/nmi_shootdown_cpus()
(Not tainted)

The RHSA-2009:0225 update resolved this issue by not calling printk()
during a crash. It was later discovered that this fix did not resolve
the issue in all cases, since there was one condition where printk()
was still being called: at a warning condition inside the mdelay()
call.

This update replaces mdelay() calls with udelay(), where such a
warning condition does not exist, which fully resolves this issue,
allowing Alt+SysRq+C to work as expected. (BZ#588211)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1188.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0439.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/25");
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
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-2.6.18-128.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-2.6.18-128.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-2.6.18-128.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-PAE-2.6.18-128.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-PAE-devel-2.6.18-128.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-debug-2.6.18-128.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-debug-2.6.18-128.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-debug-2.6.18-128.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-debug-devel-2.6.18-128.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-debug-devel-2.6.18-128.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-debug-devel-2.6.18-128.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-devel-2.6.18-128.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-devel-2.6.18-128.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-devel-2.6.18-128.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", reference:"kernel-doc-2.6.18-128.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"kernel-headers-2.6.18-128.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-headers-2.6.18-128.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-headers-2.6.18-128.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-kdump-2.6.18-128.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-kdump-devel-2.6.18-128.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-xen-2.6.18-128.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-xen-2.6.18-128.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-xen-devel-2.6.18-128.17.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-xen-devel-2.6.18-128.17.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
