#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0746. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78955);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/05 16:17:31 $");

  script_cve_id("CVE-2013-1591", "CVE-2013-1796", "CVE-2013-1797", "CVE-2013-1798");
  script_bugtraq_id(58193, 58604, 58605, 58607);
  script_xref(name:"RHSA", value:"2013:0746");

  script_name(english:"RHEL 6 : rhev-hypervisor6 (RHSA-2013:0746)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated rhev-hypervisor6 package that fixes several security issues
and various bugs is now available.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The rhev-hypervisor6 package provides a Red Hat Enterprise
Virtualization Hypervisor ISO disk image. The Red Hat Enterprise
Virtualization Hypervisor is a dedicated Kernel-based Virtual Machine
(KVM) hypervisor. It includes everything necessary to run and manage
virtual machines: A subset of the Red Hat Enterprise Linux operating
environment and the Red Hat Enterprise Virtualization Agent.

Note: Red Hat Enterprise Virtualization Hypervisor is only available
for the Intel 64 and AMD64 architectures with virtualization
extensions.

A flaw was found in the way KVM handled guest time updates when the
buffer the guest registered by writing to the MSR_KVM_SYSTEM_TIME
machine state register (MSR) crossed a page boundary. A privileged
guest user could use this flaw to crash the host or, potentially,
escalate their privileges, allowing them to execute arbitrary code at
the host kernel level. (CVE-2013-1796)

A potential use-after-free flaw was found in the way KVM handled guest
time updates when the GPA (guest physical address) the guest
registered by writing to the MSR_KVM_SYSTEM_TIME machine state
register (MSR) fell into a movable or removable memory region of the
hosting user-space process (by default, QEMU-KVM) on the host. If that
memory region is deregistered from KVM using
KVM_SET_USER_MEMORY_REGION and the allocated virtual memory reused, a
privileged guest user could potentially use this flaw to escalate
their privileges on the host. (CVE-2013-1797)

A flaw was found in the way KVM emulated IOAPIC (I/O Advanced
Programmable Interrupt Controller). A missing validation check in the
ioapic_read_indirect() function could allow a privileged guest user to
crash the host, or read a substantial portion of host kernel memory.
(CVE-2013-1798)

An integer overflow flaw was discovered in one of pixman's
manipulation routines. If a remote attacker could trick an application
using pixman into performing a certain manipulation, it could cause
the application to crash or, possibly, execute arbitrary code with the
privileges of the user running the application. (CVE-2013-1591)

Red Hat would like to thank Andrew Honig of Google for reporting
CVE-2013-1796, CVE-2013-1797, and CVE-2013-1798.

This updated package provides updated components that include fixes
for various security issues. These issues have no security impact on
Red Hat Enterprise Virtualization Hypervisor itself, however. The
security fixes included in this update address the following CVE
numbers :

CVE-2013-2266 (a bind issue)

CVE-2012-5195, CVE-2012-5526, CVE-2012-6329, and CVE-2013-1667 (perl
issues)

This update contains the fixes from the following errata :

ovirt-node: RHBA-2013:0745 libvirt: RHBA-2013:0725 vdsm:
RHBA-2013:0704 kernel: RHSA-2013:0744

Users of the Red Hat Enterprise Virtualization Hypervisor are advised
to upgrade to this updated package, which corrects these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1591.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1796.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1797.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1798.html"
  );
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux/6/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64c6b598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://rhn.redhat.com/errata/RHBA-2013-0745.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://rhn.redhat.com/errata/RHBA-2013-0725.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://rhn.redhat.com/errata/RHBA-2013-0704.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://rhn.redhat.com/errata/RHSA-2013-0744.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0746.html"
  );
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6b506c4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rhev-hypervisor6 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhev-hypervisor6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0746";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL6", reference:"rhev-hypervisor6-6.4-20130415.0.el6_4")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rhev-hypervisor6");
  }
}
