#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0575 and 
# CentOS Errata and Security Advisory 2006:0575 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(22276);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2005-3055", "CVE-2005-3623", "CVE-2006-0038", "CVE-2006-0456", "CVE-2006-0457", "CVE-2006-0742", "CVE-2006-1052", "CVE-2006-1056", "CVE-2006-1242", "CVE-2006-1343", "CVE-2006-1857", "CVE-2006-2275", "CVE-2006-2446", "CVE-2006-2448", "CVE-2006-2934");
  script_bugtraq_id(16570, 17600);
  script_osvdb_id(19702, 22179, 23660, 23894, 24040, 24071, 24137, 24807, 25232, 25695, 26615, 26946, 26963, 26997, 28551);
  script_xref(name:"RHSA", value:"2006:0575");

  script_name(english:"CentOS 4 : kernel (CESA-2006:0575)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages are now available as part of ongoing support
and maintenance of Red Hat Enterprise Linux version 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

This is the fourth regular update to Red Hat Enterprise Linux 4.

New features introduced in this update include :

* Device Mapper mirroring support

* IDE diskdump support

* x86, AMD64 and Intel EM64T: Multi-core scheduler support
enhancements

* Itanium: perfmon support for Montecito

* much improved support for IBM x460

* AMD PowerNow! patches to support Opteron Rev G

* Vmalloc support > 64MB

The following device drivers have been upgraded to new versions :

ipmi: 33.11 to 33.13 ib_mthca: 0.06 to 0.08 bnx2: 1.4.30 to 1.4.38
bonding: 2.6.1 to 2.6.3 e100: 3.4.8-k2-NAPI to 3.5.10-k2-NAPI e1000:
6.1.16-k3-NAPI to 7.0.33-k2-NAPI sky2: 0.13 to 1.1 tg3: 3.43-rh to
3.52-rh ipw2100: 1.1.0 to git-1.1.4 ipw2200: 1.0.0 to git-1.0.10
3w-9xxx: 2.26.02.001 to 2.26.04.010 ips: 7.10.18 to 7.12.02
iscsi_sfnet: 4:0.1.11-2 to 4:0.1.11-3 lpfc: 0:8.0.16.18 to 0:8.0.16.27
megaraid_sas: 00.00.02.00 to 00.00.02.03-RH1 qla2xxx: 8.01.02-d4 to
8.01.04-d7 qla6312: 8.01.02-d4 to 8.01.04-d7 sata_promise: 1.03 to
1.04 sata_vsc: 1.1 to 1.2 ibmvscsic: 1.5.5 to 1.5.6 ipr: 2.0.11.1 to
2.0.11.2

Added drivers :

dcdbas: 5.6.0-2 sata_mv: 0.6 sata_qstor: 0.05 sata_uli: 0.5 skge: 1.1
stex: 2.9.0.13 pdc_adma: 0.03

This update includes fixes for the security issues :

* a flaw in the USB devio handling of device removal that allowed a
local user to cause a denial of service (crash) (CVE-2005-3055,
moderate)

* a flaw in the ACL handling of nfsd that allowed a remote user to
bypass ACLs for readonly mounted NFS file systems (CVE-2005-3623,
moderate)

* a flaw in the netfilter handling that allowed a local user with
CAP_NET_ADMIN rights to cause a buffer overflow (CVE-2006-0038, low)

* a flaw in the IBM S/390 and IBM zSeries strnlen_user() function that
allowed a local user to cause a denial of service (crash) or to
retrieve random kernel data (CVE-2006-0456, important)

* a flaw in the keyctl functions that allowed a local user to cause a
denial of service (crash) or to read sensitive kernel memory
(CVE-2006-0457, important)

* a flaw in unaligned accesses handling on Itanium processors that
allowed a local user to cause a denial of service (crash)
(CVE-2006-0742, important)

* a flaw in SELinux ptrace logic that allowed a local user with ptrace
permissions to change the tracer SID to a SID of another process
(CVE-2006-1052, moderate)

* an info leak on AMD-based x86 and x86_64 systems that allowed a
local user to retrieve the floating point exception state of a process
run by a different user (CVE-2006-1056, important)

* a flaw in IPv4 packet output handling that allowed a remote user to
bypass the zero IP ID countermeasure on systems with a disabled
firewall (CVE-2006-1242, low)

* a minor info leak in socket option handling in the network code
(CVE-2006-1343, low)

* a flaw in the HB-ACK chunk handling of SCTP that allowed a remote
user to cause a denial of service (crash) (CVE-2006-1857, moderate)

* a flaw in the SCTP implementation that allowed a remote user to
cause a denial of service (deadlock) (CVE-2006-2275, moderate)

* a flaw in the socket buffer handling that allowed a remote user to
cause a denial of service (panic) (CVE-2006-2446, important)

* a flaw in the signal handling access checking on PowerPC that
allowed a local user to cause a denial of service (crash) or read
arbitrary kernel memory on 64-bit systems (CVE-2006-2448, important)

* a flaw in the netfilter SCTP module when receiving a chunkless
packet that allowed a remote user to cause a denial of service (crash)
(CVE-2006-2934, important)

There were several bug fixes in various parts of the kernel. The
ongoing effort to resolve these problems has resulted in a marked
improvement in the reliability and scalability of Red Hat Enterprise
Linux 4."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013147.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6983b8e3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013148.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ab4db8d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-largesmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-largesmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/25");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-2.6.9-42.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-2.6.9-42.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-devel-2.6.9-42.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-devel-2.6.9-42.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-doc-2.6.9-42.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-doc-2.6.9-42.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-2.6.9-42.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-42.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-42.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-42.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-2.6.9-42.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-2.6.9-42.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-devel-2.6.9-42.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-42.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
