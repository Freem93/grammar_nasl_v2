#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0476. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79275);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/04 15:51:47 $");

  script_cve_id("CVE-2010-0430", "CVE-2010-0741", "CVE-2010-2223");
  script_bugtraq_id(64576);
  script_osvdb_id(65796, 104885);
  script_xref(name:"RHSA", value:"2010:0476");

  script_name(english:"RHEL 5 : rhev-hypervisor (RHSA-2010:0476)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated rhev-hypervisor package that fixes two security issues,
multiple bugs, and adds enhancements is now available.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The rhev-hypervisor package provides a Red Hat Enterprise
Virtualization Hypervisor ISO disk image. The Red Hat Enterprise
Virtualization Hypervisor is a dedicated Kernel-based Virtual Machine
(KVM) hypervisor. It includes everything necessary to run and manage
virtual machines: A subset of the Red Hat Enterprise Linux operating
environment and the Red Hat Enterprise Virtualization Agent.

Note: Red Hat Enterprise Virtualization Hypervisor is only available
for the Intel 64 and AMD64 architectures with virtualization
extensions.

A flaw was found in the way QEMU-KVM handled erroneous data provided
by the Linux virtio-net driver, used by guest operating systems. Due
to a deficiency in the TSO (TCP segment offloading) implementation, a
guest's virtio-net driver would transmit improper data to a certain
QEMU-KVM process on the host, causing the guest to crash. A remote
attacker could use this flaw to send specially crafted data to a
target guest system, causing that guest to crash. (CVE-2010-0741)

A flaw was found in the way the Virtual Desktop Server Manager (VDSM)
handled the removal of a virtual machine's (VM) data back end (such as
an image or a volume). When removing an image or a volume, it was not
securely deleted from its corresponding data domain as expected. A
guest user in a new, raw VM, created in a data domain that has had VMs
deleted from it, could use this flaw to read limited data from those
deleted VMs, potentially disclosing sensitive information.
(CVE-2010-2223)

This updated package provides updated components that include fixes
for security issues; however, these issues have no security impact for
Red Hat Enterprise Virtualization Hypervisor. These fixes are for dbus
issue CVE-2009-1189; kernel issues CVE-2010-0307, CVE-2010-0410,
CVE-2010-0730, CVE-2010-1085, and CVE-2010-1086; openldap issue
CVE-2009-3767; and sudo issues CVE-2010-0426, CVE-2010-0427, and
CVE-2010-1163.

This update also fixes several bugs and adds several enhancements.
Documentation for these bug fixes and enhancements is available from
http://www.redhat.com/docs/en-US/Red_Hat_Enterprise_Virtualization/2.2
/html/ Servers-5.5-2.2_Hypervisor_Security_Update

As Red Hat Enterprise Virtualization Hypervisor is based on KVM, the
bug fixes and enhancements from the KVM updates RHSA-2010:0271 and
RHBA-2010:0419 have been included in this update. Also included are
the bug fixes and enhancements from the Virtual Desktop Server Manager
(VDSM) update RHSA-2010:0473, and fence-agents update RHBA-2010:0477.

KVM: https://rhn.redhat.com/errata/RHSA-2010-0271.html and
https://rhn.redhat.com/errata/RHBA-2010-0419.html VDSM:
https://rhn.redhat.com/errata/RHSA-2010-0473.html fence-agents:
https://rhn.redhat.com/errata/RHBA-2010-0477.html

Users of the Red Hat Enterprise Virtualization Hypervisor are advised
to upgrade to this updated package, which corrects these issues and
adds these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-0430.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-0741.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-2223.html"
  );
  # http://www.redhat.com/docs/en-US/Red_Hat_Enterprise_Virtualization/2.2/html/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2705873a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0476.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected rhev-hypervisor and / or rhev-hypervisor-pxe
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhev-hypervisor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhev-hypervisor-pxe");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/17");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2010:0476";
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
  if (rpm_check(release:"RHEL5", reference:"rhev-hypervisor-5.5-2.2.4.2.el5rhev")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhev-hypervisor-pxe-5.5-2.2.4.2.el5rhev")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rhev-hypervisor / rhev-hypervisor-pxe");
  }
}
