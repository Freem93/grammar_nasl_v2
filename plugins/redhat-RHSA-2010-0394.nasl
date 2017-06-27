#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0394. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46306);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/01/04 15:51:47 $");

  script_cve_id("CVE-2010-0729", "CVE-2010-1083", "CVE-2010-1085", "CVE-2010-1086", "CVE-2010-1188");
  script_bugtraq_id(38348, 38479, 38702, 39016, 39042);
  script_osvdb_id(62387, 62507, 63080, 63453, 63632);
  script_xref(name:"RHSA", value:"2010:0394");

  script_name(english:"RHEL 4 : kernel (RHSA-2010:0394)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues, several
bugs, and add three enhancements are now available for Red Hat
Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security fixes :

* RHSA-2009:1024 introduced a flaw in the ptrace implementation on
Itanium systems. ptrace_check_attach() was not called during certain
ptrace() requests. Under certain circumstances, a local, unprivileged
user could use this flaw to call ptrace() on a process they do not
own, giving them control over that process. (CVE-2010-0729, Important)

* a flaw was found in the kernel's Unidirectional Lightweight
Encapsulation (ULE) implementation. A remote attacker could send a
specially crafted ISO MPEG-2 Transport Stream (TS) frame to a target
system, resulting in a denial of service. (CVE-2010-1086, Important)

* a use-after-free flaw was found in tcp_rcv_state_process() in the
kernel's TCP/IP protocol suite implementation. If a system using IPv6
had the IPV6_RECVPKTINFO option set on a listening socket, a remote
attacker could send an IPv6 packet to that system, causing a kernel
panic. (CVE-2010-1188, Important)

* a divide-by-zero flaw was found in azx_position_ok() in the Intel
High Definition Audio driver, snd-hda-intel. A local, unprivileged
user could trigger this flaw to cause a denial of service.
(CVE-2010-1085, Moderate)

* an information leak flaw was found in the kernel's USB
implementation. Certain USB errors could result in an uninitialized
kernel buffer being sent to user-space. An attacker with physical
access to a target system could use this flaw to cause an information
leak. (CVE-2010-1083, Low)

Red Hat would like to thank Ang Way Chuang for reporting
CVE-2010-1086.

Bug fixes :

* a regression prevented the Broadcom BCM5761 network device from
working when in the first (top) PCI-E slot of Hewlett-Packard (HP)
Z600 systems. Note: The card worked in the 2nd or 3rd PCI-E slot.
(BZ#567205)

* the Xen hypervisor supports 168 GB of RAM for 32-bit guests. The
physical address range was set incorrectly, however, causing 32-bit,
para-virtualized Red Hat Enterprise Linux 4.8 guests to crash when
launched on AMD64 or Intel 64 hosts that have more than 64 GB of RAM.
(BZ#574392)

* RHSA-2009:1024 introduced a regression, causing diskdump to fail on
systems with certain adapters using the qla2xxx driver. (BZ#577234)

* a race condition caused TX to stop in a guest using the virtio_net
driver. (BZ#580089)

* on some systems, using the 'arp_validate=3' bonding option caused
both links to show as 'down' even though the arp_target was responding
to ARP requests sent by the bonding driver. (BZ#580842)

* in some circumstances, when a Red Hat Enterprise Linux client
connected to a re-booted Windows-based NFS server, server-side
filehandle-to-inode mapping changes caused a kernel panic.
'bad_inode_ops' handling was changed to prevent this. Note:
filehandle-to-inode mapping changes may still cause errors, but not
panics. (BZ#582908)

* when installing a Red Hat Enterprise Linux 4 guest via PXE,
hard-coded fixed-size scatterlists could conflict with host requests,
causing the guest's kernel to panic. With this update, dynamically
allocated scatterlists are used, resolving this issue. (BZ#582911)

Enhancements :

* kernel support for connlimit. Note: iptables errata update
RHBA-2010:0395 is also required for connlimit to work correctly.
(BZ#563223)

* support for the Intel architectural performance monitoring subsystem
(arch_perfmon). On supported CPUs, arch_perfmon offers means to mark
performance events and options for configuring and counting these
events. (BZ#582913)

* kernel support for OProfile sampling of Intel microarchitecture
(Nehalem) CPUs. This update alone does not address OProfile support
for such CPUs. A future oprofile package update will allow OProfile to
work on Intel Nehalem CPUs. (BZ#582241)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues and add these enhancements.
The system must be rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-0729.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1083.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1085.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1086.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1188.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0394.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-largesmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-largesmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xenU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xenU-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2010:0394";
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
  if (rpm_check(release:"RHEL4", reference:"kernel-2.6.9-89.0.25.EL")) flag++;

  if (rpm_check(release:"RHEL4", reference:"kernel-devel-2.6.9-89.0.25.EL")) flag++;

  if (rpm_check(release:"RHEL4", reference:"kernel-doc-2.6.9-89.0.25.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-hugemem-2.6.9-89.0.25.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-hugemem-devel-2.6.9-89.0.25.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-89.0.25.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-89.0.25.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-smp-2.6.9-89.0.25.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-smp-2.6.9-89.0.25.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-smp-devel-2.6.9-89.0.25.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-89.0.25.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-xenU-2.6.9-89.0.25.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-xenU-2.6.9-89.0.25.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-xenU-devel-2.6.9-89.0.25.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-xenU-devel-2.6.9-89.0.25.EL")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-devel / kernel-doc / kernel-hugemem / etc");
  }
}
