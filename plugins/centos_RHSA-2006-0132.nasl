#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0132 and 
# CentOS Errata and Security Advisory 2006:0132 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21979);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2006-0095");
  script_osvdb_id(22418);
  script_xref(name:"RHSA", value:"2006:0132");

  script_name(english:"CentOS 4 : kernel (CESA-2006:0132)");
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
third regular update.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

This is the third regular kernel update to Red Hat Enterprise Linux 4.

New features introduced in this update include :

  - Open InfiniBand (OpenIB) support

  - Serial Attached SCSI support

  - NFS access control lists, asynchronous I/O

  - IA64 multi-core support and sgi updates

  - Large SMP CPU limits increased using the largesmp
    kernel: Up to 512 CPUs in ia64, 128 in ppc64, and 64 in
    AMD64 and Intel EM64T

  - Improved read-ahead performance

  - Common Internet File System (CIFS) update

  - Error Detection and Correction (EDAC) modules

  - Unisys support

There were several bug fixes in various parts of the kernel. The
ongoing effort to resolve these problems has resulted in a marked
improvement in the reliability and scalability of Red Hat Enterprise
Linux 4.

The following security bug was fixed in this update :

  - dm-crypt did not clear a structure before freeing it,
    which could allow local users to discover information
    about cryptographic keys (CVE-2006-0095)

The following device drivers have been upgraded to new versions :

cciss: 2.6.8 to 2.6.8-rh1 ipmi_devintf: 33.4 to 33.11 ipmi_msghandler:
33.4 to 33.11 ipmi_poweroff: 33.4 to 33.11 ipmi_si: 33.4 to 33.11
ipmi_watchdog: 33.4 to 33.11 mptbase: 3.02.18 to 3.02.60.01rh e1000:
6.0.54-k2-NAPI to 6.1.16-k2-NAPI ixgb: 1.0.95-k2-NAPI to
1.0.100-k2-NAPI tg3: 3.27-rh to 3.43-rh aacraid: 1.1.2-lk2 to
1.1-5[2412] ahci: 1.01 to 1.2 ata_piix: 1.03 to 1.05 iscsi_sfnet:
4:0.1.11-1 to 4:0.1.11-2 libata: 1.11 to 1.20 qla2100: 8.01.00b5-rh2
to 8.01.02-d3 qla2200: 8.01.00b5-rh2 to 8.01.02-d3 qla2300:
8.01.00b5-rh2 to 8.01.02-d3 qla2322: 8.01.00b5-rh2 to 8.01.02-d3
qla2xxx: 8.01.00b5-rh2 to 8.01.02-d3 qla6312: 8.01.00b5-rh2 to
8.01.02-d3 sata_nv: 0.6 to 0.8 sata_promise: 1.01 to 1.03 sata_svw:
1.06 to 1.07 sata_sx4: 0.7 to 0.8 sata_vsc: 1.0 to 1.1 cifs: 1.20 to
1.34

Added drivers :

bnx2: 1.4.25 dell_rbu: 0.7 hangcheck-timer: 0.9.0 ib_mthca: 0.06
megaraid_sas: 00.00.02.00 qla2400: 8.01.02-d3 typhoon: 1.5.7

All Red Hat Enterprise Linux 4 users are advised to upgrade their
kernels to the packages associated with their machine architectures
and configurations as listed in this erratum."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-March/012713.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?96ab3796"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-March/012732.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9e7cc544"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-March/012739.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?12694f11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"kernel-2.6.9-34.EL")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kernel-devel-2.6.9-34.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-doc-2.6.9-34.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-doc-2.6.9-34.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-2.6.9-34.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-34.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"kernel-largesmp-2.6.9-34.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-34.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"kernel-largesmp-devel-2.6.9-34.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-34.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-2.6.9-34.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-2.6.9-34.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-devel-2.6.9-34.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-34.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
