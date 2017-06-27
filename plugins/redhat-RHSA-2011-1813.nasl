#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1813. The text 
# itself is copyright (C) Red Hat, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(64015);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/08/18 18:39:01 $");

  script_cve_id("CVE-2011-2482", "CVE-2011-2491", "CVE-2011-2495", "CVE-2011-2517", "CVE-2011-2519", "CVE-2011-2901");
  script_bugtraq_id(48538, 49141, 49370, 49373, 49375, 49408);
  script_xref(name:"RHSA", value:"2011:1813");

  script_name(english:"RHEL 5 : kernel (RHSA-2011:1813)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix several security issues and various
bugs are now available for Red Hat Enterprise Linux 5.6 Extended
Update Support.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

These packages contain the Linux kernel.

This update fixes the following security issues :

* A flaw in the Stream Control Transmission Protocol (SCTP)
implementation could allow a remote attacker to cause a denial of
service by sending a specially crafted SCTP packet to a target system.
(CVE-2011-2482, Important)

If you do not run applications that use SCTP, you can prevent the sctp
module from being loaded by adding the following to the end of the
'/etc/modprobe.d/blacklist.conf' file :

blacklist sctp

This way, the sctp module cannot be loaded accidentally, which may
occur if an application that requires SCTP is started. A reboot is not
necessary for this change to take effect.

* A flaw in the client-side NFS Lock Manager (NLM) implementation
could allow a local, unprivileged user to cause a denial of service.
(CVE-2011-2491, Important)

* Flaws in the netlink-based wireless configuration interface could
allow a local user, who has the CAP_NET_ADMIN capability, to cause a
denial of service or escalate their privileges on systems that have an
active wireless interface. (CVE-2011-2517, Important)

* A flaw was found in the way the Linux kernel's Xen hypervisor
implementation emulated the SAHF instruction. When using a
fully-virtualized guest on a host that does not use hardware assisted
paging (HAP), such as those running CPUs that do not have support for
(or those that have it disabled) Intel Extended Page Tables (EPT) or
AMD Virtualization (AMD-V) Rapid Virtualization Indexing (RVI), a
privileged guest user could trigger this flaw to cause the hypervisor
to crash. (CVE-2011-2519, Moderate)

* A flaw in the __addr_ok() macro in the Linux kernel's Xen hypervisor
implementation when running on 64-bit systems could allow a privileged
guest user to crash the hypervisor. (CVE-2011-2901, Moderate)

* /proc/[PID]/io is world-readable by default. Previously, these files
could be read without any further restrictions. A local, unprivileged
user could read these files, belonging to other, possibly privileged
processes to gather confidential information, such as the length of a
password used in a process. (CVE-2011-2495, Low)

Red Hat would like to thank Vasily Averin for reporting CVE-2011-2491,
and Vasiliy Kulikov of Openwall for reporting CVE-2011-2495.

This update also fixes the following bugs :

* On Broadcom PCI cards that use the tg3 driver, the operational state
of a network device, represented by the value in
'/sys/class/net/ethX/operstate', was not initialized by default.
Consequently, the state was reported as 'unknown' when the tg3 network
device was actually in the 'up' state. This update modifies the tg3
driver to properly set the operstate value. (BZ#744699)

* A KVM (Kernel-based Virtual Machine) guest can get preempted by the
host, when a higher priority process needs to run. When a guest is not
running for several timer interrupts in a row, ticks could be lost,
resulting in the jiffies timer advancing slower than expected and
timeouts taking longer than expected. To correct for the issue of lost
ticks, do_timer_tsc_timekeeping() checks a reference clock source
(kvm-clock when running as a KVM guest) to see if timer interrupts
have been missed. If so, jiffies is incremented by the number of
missed timer interrupts, ensuring that programs are woken up on time.
(BZ#747874)

* When a block device object was allocated, the bd_super field was not
being explicitly initialized to NULL. Previously, users of the block
device object could set bd_super to NULL when the object was released
by calling the kill_block_super() function. Certain third-party file
systems do not always use this function, and bd_super could therefore
become uninitialized when the object was allocated again. This could
cause a kernel panic in the blkdev_releasepage() function, when the
uninitialized bd_super field was dereferenced. Now, bd_super is
properly initialized in the bdget() function, and the kernel panic no
longer occurs. (BZ#751137)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2482.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2491.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2495.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2517.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2519.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2901.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1813.html"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/13");
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
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-2.6.18-238.31.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-2.6.18-238.31.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-2.6.18-238.31.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-PAE-2.6.18-238.31.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-PAE-devel-2.6.18-238.31.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-debug-2.6.18-238.31.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-debug-2.6.18-238.31.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-debug-2.6.18-238.31.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-debug-devel-2.6.18-238.31.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-debug-devel-2.6.18-238.31.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-debug-devel-2.6.18-238.31.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-devel-2.6.18-238.31.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-devel-2.6.18-238.31.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-devel-2.6.18-238.31.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", reference:"kernel-doc-2.6.18-238.31.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"kernel-headers-2.6.18-238.31.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-headers-2.6.18-238.31.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-headers-2.6.18-238.31.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-kdump-2.6.18-238.31.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-kdump-devel-2.6.18-238.31.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-xen-2.6.18-238.31.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-xen-2.6.18-238.31.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-xen-devel-2.6.18-238.31.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-xen-devel-2.6.18-238.31.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
