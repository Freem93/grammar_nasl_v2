#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0285 and 
# CentOS Errata and Security Advisory 2014:0285 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(72986);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/06/20 17:19:58 $");

  script_cve_id("CVE-2013-2929", "CVE-2013-4483", "CVE-2013-4554", "CVE-2013-6381", "CVE-2013-6383", "CVE-2013-6885", "CVE-2013-7263");
  script_bugtraq_id(63445, 63888, 63890, 63931, 63983, 64111, 64686);
  script_osvdb_id(99161, 99324, 100422);
  script_xref(name:"RHSA", value:"2014:0285");

  script_name(english:"CentOS 5 : kernel (CESA-2014:0285)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues, several
bugs, and add one enhancement are now available for Red Hat Enterprise
Linux 5.

The Red Hat Security Response Team has rated this update as having
Important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* A buffer overflow flaw was found in the way the qeth_snmp_command()
function in the Linux kernel's QETH network device driver
implementation handled SNMP IOCTL requests with an out-of-bounds
length. A local, unprivileged user could use this flaw to crash the
system or, potentially, escalate their privileges on the system.
(CVE-2013-6381, Important)

* A flaw was found in the way the ipc_rcu_putref() function in the
Linux kernel's IPC implementation handled reference counter
decrementing. A local, unprivileged user could use this flaw to
trigger an Out of Memory (OOM) condition and, potentially, crash the
system. (CVE-2013-4483, Moderate)

* It was found that the Xen hypervisor implementation did not
correctly check privileges of hypercall attempts made by HVM guests,
allowing hypercalls to be invoked from protection rings 1 and 2 in
addition to ring 0. A local attacker in an HVM guest able to execute
code on privilege levels 1 and 2 could potentially use this flaw to
further escalate their privileges in that guest. Note: Xen HVM guests
running unmodified versions of Red Hat Enterprise Linux and Microsoft
Windows are not affected by this issue because they are known to only
use protection rings 0 (kernel) and 3 (userspace). (CVE-2013-4554,
Moderate)

* A flaw was found in the way the Linux kernel's Adaptec RAID
controller (aacraid) checked permissions of compat IOCTLs. A local
attacker could use this flaw to bypass intended security restrictions.
(CVE-2013-6383, Moderate)

* It was found that, under specific circumstances, a combination of
write operations to write-combined memory and locked CPU instructions
may cause a core hang on certain AMD CPUs (for more information, refer
to AMD CPU erratum 793 linked in the References section). A privileged
user in a guest running under the Xen hypervisor could use this flaw
to cause a denial of service on the host system. This update adds a
workaround to the Xen hypervisor implementation, which mitigates the
AMD CPU issue. Note: this issue only affects AMD Family 16h Models
00h-0Fh Processors. Non-AMD CPUs are not vulnerable. (CVE-2013-6885,
Moderate)

* It was found that certain protocol handlers in the Linux kernel's
networking implementation could set the addr_len value without
initializing the associated data structure. A local, unprivileged user
could use this flaw to leak kernel stack memory to user space using
the recvmsg, recvfrom, and recvmmsg system calls. (CVE-2013-7263, Low)

* A flaw was found in the way the get_dumpable() function return value
was interpreted in the ptrace subsystem of the Linux kernel. When
'fs.suid_dumpable' was set to 2, a local, unprivileged local user
could use this flaw to bypass intended ptrace restrictions and obtain
potentially sensitive information. (CVE-2013-2929, Low)

Red Hat would like to thank Vladimir Davydov of Parallels for
reporting CVE-2013-4483 and the Xen project for reporting
CVE-2013-4554 and CVE-2013-6885. Upstream acknowledges Jan Beulich as
the original reporter of CVE-2013-4554 and CVE-2013-6885.

This update also fixes several bugs and adds one enhancement.
Documentation for these changes will be available shortly from the
Technical Notes document linked to in the References section.

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add this
enhancement. The system must be rebooted for this update to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-March/020199.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7249438"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/14");
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
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-371.6.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-371.6.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-371.6.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-371.6.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-371.6.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-371.6.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-371.6.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-371.6.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-371.6.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-371.6.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
