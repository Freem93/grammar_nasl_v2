#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:514 and 
# CentOS Errata and Security Advisory 2005:514 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21943);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2005-0756", "CVE-2005-1265", "CVE-2005-1761", "CVE-2005-1762", "CVE-2005-1763", "CVE-2005-2098", "CVE-2005-2099", "CVE-2005-2100", "CVE-2005-2456", "CVE-2005-2490", "CVE-2005-2492", "CVE-2005-2555", "CVE-2005-2801", "CVE-2005-2872", "CVE-2005-3105", "CVE-2005-3274", "CVE-2005-3275", "CVE-2005-4886", "CVE-2006-5871");
  script_osvdb_id(17233, 17234, 17479, 17546, 17693, 18555, 18651, 18652, 18978, 19260, 19261, 19314, 19430, 20424);
  script_xref(name:"RHSA", value:"2005:514");

  script_name(english:"CentOS 4 : kernel (CESA-2005:514)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages are now available as part of ongoing support
and maintenance of Red Hat Enterprise Linux version 4. This is the
second regular update.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

This is the second regular kernel update to Red Hat Enterprise Linux
4.

New features introduced in this update include: - Audit support -
systemtap - kprobes, relayfs - Keyring support - iSCSI Initiator -
iscsi_sfnet 4:0.1.11-1 - Device mapper multipath support - Intel dual
core support - esb2 chipset support - Increased exec-shield coverage -
Dirty page tracking for HA systems - Diskdump -- allow partial
diskdumps and directing to swap

There were several bug fixes in various parts of the kernel. The
ongoing effort to resolve these problems has resulted in a marked
improvement in the reliability and scalability of Red Hat Enterprise
Linux 4.

The following security bugs were fixed in this update, detailed below
with corresponding CAN names available from the Common Vulnerabilities
and Exposures project (cve.mitre.org) :

  - flaws in ptrace() syscall handling on 64-bit systems
    that allowed a local user to cause a denial of service
    (crash) (CVE-2005-0756, CVE-2005-1761, CVE-2005-1762,
    CVE-2005-1763)

  - flaws in IPSEC network handling that allowed a local
    user to cause a denial of service or potentially gain
    privileges (CVE-2005-2456, CVE-2005-2555)

  - a flaw in sendmsg() syscall handling on 64-bit systems
    that allowed a local user to cause a denial of service
    or potentially gain privileges (CVE-2005-2490)

  - a flaw in sendmsg() syscall handling that allowed a
    local user to cause a denial of service by altering
    hardware state (CVE-2005-2492)

  - a flaw that prevented the topdown allocator from
    allocating mmap areas all the way down to address zero
    (CVE-2005-1265)

  - flaws dealing with keyrings that could cause a local
    denial of service (CVE-2005-2098, CVE-2005-2099)

  - a flaw in the 4GB split patch that could allow a local
    denial of service (CVE-2005-2100)

  - a xattr sharing bug in the ext2 and ext3 file systems
    that could cause default ACLs to disappear
    (CVE-2005-2801)

  - a flaw in the ipt_recent module on 64-bit architectures
    which could allow a remote denial of service
    (CVE-2005-2872)

The following device drivers have been upgraded to new versions :

qla2100 --------- 8.00.00b21-k to 8.01.00b5-rh2 qla2200 ---------
8.00.00b21-k to 8.01.00b5-rh2 qla2300 --------- 8.00.00b21-k to
8.01.00b5-rh2 qla2322 --------- 8.00.00b21-k to 8.01.00b5-rh2 qla2xxx
--------- 8.00.00b21-k to 8.01.00b5-rh2 qla6312 --------- 8.00.00b21-k
to 8.01.00b5-rh2 megaraid_mbox --- 2.20.4.5 to 2.20.4.6 megaraid_mm
----- 2.20.2.5 to 2.20.2.6 lpfc ------------ 0:8.0.16.6_x2 to
0:8.0.16.17 cciss ----------- 2.6.4 to 2.6.6 ipw2100 --------- 1.0.3
to 1.1.0 tg3 ------------- 3.22-rh to 3.27-rh e100 ------------
3.3.6-k2-NAPI to 3.4.8-k2-NAPI e1000 ----------- 5.6.10.1-k2-NAPI to
6.0.54-k2-NAPI 3c59x ----------- LK1.1.19 mptbase --------- 3.01.16 to
3.02.18 ixgb ------------ 1.0.66 to 1.0.95-k2-NAPI libata ----------
1.10 to 1.11 sata_via -------- 1.0 to 1.1 sata_ahci ------- 1.00 to
1.01 sata_qstor ------ 0.04 sata_sil -------- 0.8 to 0.9 sata_svw
-------- 1.05 to 1.06 s390: crypto ---- 1.31 to 1.57 s390: zfcp ------
s390: CTC-MPC --- s390: dasd ------- s390: cio ------- s390: qeth
------

All Red Hat Enterprise Linux 4 users are advised to upgrade their
kernels to the packages associated with their machine architectures
and configurations as listed in this erratum."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012244.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52b44867"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"kernel-2.6.9-22.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"kernel-devel-2.6.9-22.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"kernel-doc-2.6.9-22.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
