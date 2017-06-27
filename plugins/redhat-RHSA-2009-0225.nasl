#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0225. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35434);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/01/03 17:16:35 $");

  script_cve_id("CVE-2008-5029", "CVE-2008-5079", "CVE-2008-5182", "CVE-2008-5300");
  script_bugtraq_id(32154, 32676, 33503);
  script_xref(name:"RHSA", value:"2009:0225");

  script_name(english:"RHEL 5 : kernel (RHSA-2009:0225)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix three security issues, address
several hundred bugs and add numerous enhancements are now available
as part of the ongoing support and maintenance of Red Hat Enterprise
Linux version 5. This is the third regular update.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Linux kernel (the core of the Linux operating system)

These updated packages contain 730 bug fixes and enhancements for the
Linux kernel. Space precludes a detailed description of each of these
changes in this advisory and users are therefore directed to the
release notes for Red Hat Enterprise Linux 5.3 for information on 97
of the most significant of these changes.

Details of three security-related bug fixes are set out below, along
with notes on other broad categories of change not covered in the
release notes. For more detailed information on specific bug fixes or
enhancements, please consult the Bugzilla numbers listed in this
advisory.

* when fput() was called to close a socket, the __scm_destroy()
function in the Linux kernel could make indirect recursive calls to
itself. This could, potentially, lead to a denial of service issue.
(CVE-2008-5029, Important)

* a flaw was found in the Asynchronous Transfer Mode (ATM) subsystem.
A local, unprivileged user could use the flaw to listen on the same
socket more than once, possibly causing a denial of service.
(CVE-2008-5079, Important)

* a race condition was found in the Linux kernel 'inotify' watch
removal and umount implementation. This could allow a local,
unprivileged user to cause a privilege escalation or a denial of
service. (CVE-2008-5182, Important)

* Bug fixes and enhancements are provided for :

* support for specific NICs, including products from the following
manufacturers: Broadcom Chelsio Cisco Intel Marvell NetXen Realtek Sun

* Fiber Channel support, including support for Qlogic qla2xxx,
qla4xxx, and qla84xx HBAs and the FCoE, FCP, and zFCP protocols.

* support for various CPUs, including: AMD Opteron processors with 45
nm SOI ('Shanghai') AMD Turion Ultra processors Cell processors Intel
Core i7 processors

* Xen support, including issues specific to the IA64 platform, systems
using AMD processors, and Dell Optiplex GX280 systems

* ext3, ext4, GFS2, NFS, and SPUFS

* Infiniband (including eHCA, eHEA, and IPoIB) support

* common I/O (CIO), direct I/O (DIO), and queued direct I/O (qdio)
support

* the kernel distributed lock manager (DLM)

* hardware issues with: SCSI, IEEE 1394 (FireWire), RAID (including
issues specific to Adaptec controllers), SATA (including NCQ), PCI,
audio, serial connections, tape-drives, and USB

* ACPI, some of a general nature and some related to specific hardware
including: certain Lenovo Thinkpad notebooks, HP DC7700 systems, and
certain machines based on Intel Centrino processor technology.

* CIFS, including Kerberos support and a tech-preview of DFS support

* networking support, including IPv6, PPPoE, and IPSec

* support for Intel chipsets, including: Intel Cantiga chipsets Intel
Eagle Lake chipsets Intel i915 chipsets Intel i965 chipsets Intel Ibex
Peak chipsets Intel chipsets offering QuickPath Interconnects (QPI)

* device mapping issues, including some in device mapper itself

* various issues specific to IA64 and PPC

* CCISS, including support for Compaq SMART Array controllers P711m
and P712m and other new hardware

* various issues affecting specific HP systems, including: DL785G5
XW4800 XW8600 XW8600 XW9400

* IOMMU support, including specific issues with AMD and IBM Calgary
hardware

* the audit subsystem

* DASD support

* iSCSI support, including issues specific to Chelsio T3 adapters

* LVM issues

* SCTP management information base (MIB) support

* issues with: autofs, kdump, kobject_add, libata, lpar, ptrace, and
utrace

* IBM Power platforms using Enhanced I/O Error Handling (EEH)

* EDAC issues for AMD K8 and Intel i5000

* ALSA, including support for new hardware

* futex support

* hugepage support

* Intelligent Platform Management Interface (IPMI) support

* issues affecting NEC/Stratus servers

* OFED support

* SELinux

* various Virtio issues

All users are advised to upgrade to these updated packages, which
resolve these issues and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-5029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-5079.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-5182.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-5300.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-0225.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(362, 399);

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2009:0225";
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
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-2.6.18-128.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-2.6.18-128.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-2.6.18-128.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-PAE-2.6.18-128.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-PAE-devel-2.6.18-128.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-debug-2.6.18-128.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-debug-2.6.18-128.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-debug-2.6.18-128.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-debug-devel-2.6.18-128.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-debug-devel-2.6.18-128.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-debug-devel-2.6.18-128.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-devel-2.6.18-128.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-devel-2.6.18-128.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-devel-2.6.18-128.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"kernel-doc-2.6.18-128.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"kernel-headers-2.6.18-128.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-headers-2.6.18-128.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-headers-2.6.18-128.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-kdump-2.6.18-128.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-kdump-devel-2.6.18-128.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-xen-2.6.18-128.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-xen-2.6.18-128.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-xen-devel-2.6.18-128.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-xen-devel-2.6.18-128.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-PAE / kernel-PAE-devel / kernel-debug / etc");
  }
}
