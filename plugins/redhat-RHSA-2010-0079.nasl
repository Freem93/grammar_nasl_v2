#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0079. The text 
# itself is copyright (C) Red Hat, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63915);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/10 18:05:23 $");

  script_cve_id("CVE-2007-4567", "CVE-2007-5966", "CVE-2009-0778", "CVE-2009-0834", "CVE-2009-1385", "CVE-2009-1895", "CVE-2009-4536", "CVE-2009-4537", "CVE-2009-4538");
  script_bugtraq_id(35647, 37519, 37521, 37523);
  script_xref(name:"RHSA", value:"2010:0079");

  script_name(english:"RHEL 5 : kernel (RHSA-2010:0079)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 5.2 Extended
Update Support.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* a flaw was found in the IPv6 Extension Header (EH) handling
implementation in the Linux kernel. The skb->dst data structure was
not properly validated in the ipv6_hop_jumbo() function. This could
possibly lead to a remote denial of service. (CVE-2007-4567,
Important)

* the possibility of a timeout value overflow was found in the Linux
kernel high-resolution timers functionality, hrtimers. This could
allow a local, unprivileged user to execute arbitrary code, or cause a
denial of service (kernel panic). (CVE-2007-5966, Important)

* memory leaks were found on some error paths in the icmp_send()
function in the Linux kernel. This could, potentially, cause the
network connectivity to cease. (CVE-2009-0778, Important)

* a deficiency was found in the Linux kernel system call auditing
implementation on 64-bit systems. This could allow a local,
unprivileged user to circumvent a system call audit configuration, if
that configuration filtered based on the 'syscall' number or
arguments. (CVE-2009-0834, Important)

* a flaw was found in the Intel PRO/1000 Linux driver (e1000) in the
Linux kernel. Frames with sizes near the MTU of an interface may be
split across multiple hardware receive descriptors. Receipt of such a
frame could leak through a validation check, leading to a corruption
of the length check. A remote attacker could use this flaw to send a
specially crafted packet that would cause a denial of service or code
execution. (CVE-2009-1385, Important)

* the ADDR_COMPAT_LAYOUT and MMAP_PAGE_ZERO flags were not cleared
when a setuid or setgid program was executed. A local, unprivileged
user could use this flaw to bypass the mmap_min_addr protection
mechanism and perform a NULL pointer dereference attack, or bypass the
Address Space Layout Randomization (ASLR) security feature.
(CVE-2009-1895, Important)

* a flaw was found in each of the following Intel PRO/1000 Linux
drivers in the Linux kernel: e1000 and e1000e. A remote attacker using
packets larger than the MTU could bypass the existing fragment check,
resulting in partial, invalid frames being passed to the network
stack. These flaws could also possibly be used to trigger a remote
denial of service. (CVE-2009-4536, CVE-2009-4538, Important)

* a flaw was found in the Realtek r8169 Ethernet driver in the Linux
kernel. Receiving overly-long frames with a certain revision of the
network cards supported by this driver could possibly result in a
remote denial of service. (CVE-2009-4537, Important)

Note: This update also fixes several bugs. Documentation for these bug
fixes will be available shortly from
www.redhat.com/docs/en-US/errata/RHSA-2010-0079/Kernel_Security_Update
/ index.html

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-4567.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-5966.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0778.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0834.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-1385.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-1895.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-4536.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-4537.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-4538.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0079.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(16, 20, 189, 264);

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i686", reference:"kernel-2.6.18-92.1.35.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"s390x", reference:"kernel-2.6.18-92.1.35.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"x86_64", reference:"kernel-2.6.18-92.1.35.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i686", reference:"kernel-PAE-2.6.18-92.1.35.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i686", reference:"kernel-PAE-devel-2.6.18-92.1.35.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i686", reference:"kernel-debug-2.6.18-92.1.35.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"s390x", reference:"kernel-debug-2.6.18-92.1.35.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"x86_64", reference:"kernel-debug-2.6.18-92.1.35.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i686", reference:"kernel-debug-devel-2.6.18-92.1.35.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"s390x", reference:"kernel-debug-devel-2.6.18-92.1.35.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"x86_64", reference:"kernel-debug-devel-2.6.18-92.1.35.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i686", reference:"kernel-devel-2.6.18-92.1.35.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"s390x", reference:"kernel-devel-2.6.18-92.1.35.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"x86_64", reference:"kernel-devel-2.6.18-92.1.35.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", reference:"kernel-doc-2.6.18-92.1.35.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i386", reference:"kernel-headers-2.6.18-92.1.35.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"s390x", reference:"kernel-headers-2.6.18-92.1.35.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"x86_64", reference:"kernel-headers-2.6.18-92.1.35.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"s390x", reference:"kernel-kdump-2.6.18-92.1.35.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"s390x", reference:"kernel-kdump-devel-2.6.18-92.1.35.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i686", reference:"kernel-xen-2.6.18-92.1.35.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"x86_64", reference:"kernel-xen-2.6.18-92.1.35.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i686", reference:"kernel-xen-devel-2.6.18-92.1.35.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"x86_64", reference:"kernel-xen-devel-2.6.18-92.1.35.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
