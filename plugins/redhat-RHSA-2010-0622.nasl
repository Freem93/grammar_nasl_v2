#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0622. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79276);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/01/04 15:51:48 $");

  script_cve_id("CVE-2010-0428", "CVE-2010-0429", "CVE-2010-0431", "CVE-2010-0435", "CVE-2010-2784", "CVE-2010-2811");
  script_bugtraq_id(42580);
  script_osvdb_id(67469, 67473, 67474, 67475, 67476, 67477);
  script_xref(name:"RHSA", value:"2010:0622");

  script_name(english:"RHEL 5 : rhev-hypervisor (RHSA-2010:0622)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rhev-hypervisor packages that fix multiple security issues and
two bugs are now available.

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

It was found that the libspice component of QEMU-KVM on the host did
not validate all pointers provided from a guest system's QXL graphics
card driver. A privileged guest user could use this flaw to cause the
host to dereference an invalid pointer, causing the guest to crash
(denial of service) or, possibly, resulting in the privileged guest
user escalating their privileges on the host. (CVE-2010-0428)

It was found that the libspice component of QEMU-KVM on the host could
be forced to perform certain memory management operations on memory
addresses controlled by a guest. A privileged guest user could use
this flaw to crash the guest (denial of service) or, possibly,
escalate their privileges on the host. (CVE-2010-0429)

It was found that QEMU-KVM on the host did not validate all pointers
provided from a guest system's QXL graphics card driver. A privileged
guest user could use this flaw to cause the host to dereference an
invalid pointer, causing the guest to crash (denial of service) or,
possibly, resulting in the privileged guest user escalating their
privileges on the host. (CVE-2010-0431)

A flaw was found in QEMU-KVM, allowing the guest some control over the
index used to access the callback array during sub-page MMIO
initialization. A privileged guest user could use this flaw to crash
the guest (denial of service) or, possibly, escalate their privileges
on the host. (CVE-2010-2784)

A NULL pointer dereference flaw was found when Red Hat Enterprise
Virtualization Hypervisor was run on a system that has a processor
with the Intel VT-x extension enabled. A privileged guest user could
use this flaw to trick the host into emulating a certain instruction,
which could crash the host (denial of service). (CVE-2010-0435)

A flaw was found in the way VDSM accepted SSL connections. An attacker
could trigger this flaw by creating a crafted SSL connection to VDSM,
preventing VDSM from accepting SSL connections from other users.
(CVE-2010-2811)

These updated packages provide updated components that include fixes
for security issues; however, these issues have no security impact for
Red Hat Enterprise Virtualization Hypervisor. These fixes are for
avahi issues CVE-2009-0758 and CVE-2010-2244; freetype issues
CVE-2010-1797, CVE-2010-2498, CVE-2010-2499, CVE-2010-2500,
CVE-2010-2519, CVE-2010-2527, and CVE-2010-2541; kernel issues
CVE-2010-1084, CVE-2010-2066, CVE-2010-2070, CVE-2010-2226,
CVE-2010-2248, CVE-2010-2521, and CVE-2010-2524; and openldap issues
CVE-2010-0211 and CVE-2010-0212.

These updated rhev-hypervisor packages also fix two bugs.
Documentation for these bug fixes will be available shortly from
http://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Virtualization_fo
r_Servers /2.2/html/Technical_Notes/index.html

As Red Hat Enterprise Virtualization Hypervisor is based on KVM, the
bug fixes from the KVM update RHSA-2010:0627 have been included in
this update. Also included are the bug fixes from the VDSM update
RHSA-2010:0628.

KVM: https://rhn.redhat.com/errata/RHSA-2010-0627.html VDSM:
https://rhn.redhat.com/errata/RHSA-2010-0628.html

Users of Red Hat Enterprise Virtualization Hypervisor are advised to
upgrade to these updated rhev-hypervisor packages, which resolve these
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-0428.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-0429.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-0431.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-0435.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-2784.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-2811.html"
  );
  # http://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Virtualization_for_Servers
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cca30549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0622.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected rhev-hypervisor and / or rhev-hypervisor-pxe
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhev-hypervisor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhev-hypervisor-pxe");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/19");
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
  rhsa = "RHSA-2010:0622";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL5", reference:"rhev-hypervisor-5.5-2.2.6.1.el5_5rhev2_2")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhev-hypervisor-pxe-5.5-2.2.6.1.el5_5rhev2_2")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
