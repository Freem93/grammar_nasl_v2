#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0665. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33581);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/03 17:16:34 $");

  script_cve_id("CVE-2006-4145", "CVE-2008-2812");
  script_bugtraq_id(19562, 30076);
  script_xref(name:"RHSA", value:"2008:0665");

  script_name(english:"RHEL 4 : kernel (RHSA-2008:0665)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages are now available as part of ongoing support
and maintenance of Red Hat Enterprise Linux 4. This is the seventh
regular update.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Kernel Feature Support: * iostat displays I/O performance for
partitions * I/O task accounting added to getrusage(), allowing
comprehensive core statistics * page cache pages count added to
show_mem() output * tux O_ATOMICLOOKUP flag removed from the open()
system call: replaced with O_CLOEXEC * the kernel now exports process
limit information to /proc/[PID]/limits * implement udp_poll() to
reduce likelihood of false positives returned from select() * the
TCP_RTO_MIN parameter can now be configured to a maximum of 3000
milliseconds. This is configured using 'ip route' * update CIFS to
version 1.50

Added Features: * nfs.enable_ino64 boot command line parameter: enable
and disable 32-bit inode numbers when using NFS * tick 'divider'
kernel boot parameter: reduce CPU overhead, and increase efficiency at
the cost of lowering timing accuracy *
/proc/sys/vm/nfs-writeback-lowmem-only tunable parameter: resolve NFS
read performance * /proc/sys/vm/write-mapped tunable option, allowing
the option of faster NFS reads * support for Large Receive Offload as
a networking module * core dump masking, allowing a core dump process
to skip the shared memory segments of a process

Virtualization: * para-virtualized network and block device drivers,
to increase fully-virtualized guest performance * support for more
than three VNIF numbers per guest domain

Platform Support: * AMD ATI SB800 SATA controller, AMD ATI SB600 and
SB700 40-pin IDE cable * 64-bit DMA support on AMD ATI SB700 * PCI
device IDs to support Intel ICH10 * /dev/msr[0-n] device files *
powernow-k8 as a module * SLB shadow buffer support for IBM POWER6
systems * support for CPU frequencies greater than 32-bit on IBM
POWER5, IBM POWER6 * floating point load and store handler for IBM
POWER6

Added Drivers and Updates: * ixgbe 1.1.18, for the Intel 82598 10GB
ethernet controller * bnx2x 1.40.22, for network adapters on the
Broadcom 5710 chipset * dm-hp-sw 1.0.0, for HP Active/Standby * zfcp
version and bug fixes * qdio to fix FCP/SCSI write I/O expiring on
LPARs * cio bug fixes * eHEA latest upstream, and netdump and
netconsole support * ipr driver support for dual SAS RAID controllers
* correct CPU cache info and SATA support for Intel Tolapai *
i5000_edac support for Intel 5000 chipsets * i3000_edac support for
Intel 3000 and 3010 chipsets * add i2c_piix4 module on 64-bit systems
to support AMD ATI SB600, 700 and 800 * i2c-i801 support for Intel
Tolapai * qla4xxx: 5.01.01-d2 to 5.01.02-d4-rhel4.7-00 * qla2xxx:
8.01.07-d4 to 8.01.07-d4-rhel4.7-02 * cciss: 2.6.16 to 2.6.20 *
mptfusion: 3.02.99.00rh to 3.12.19.00rh * lpfc:0: 8.0.16.34 to
8.0.16.40 * megaraid_sas: 00.00.03.13 to 00.00.03.18-rh1 * stex:
3.0.0.1 to 3.6.0101.2 * arcmsr: 1.20.00.13 to 1.20.00.15.rh4u7 *
aacraid: 1.1-5[2441] to 1.1.5[2455]

Miscellaneous Updates: * OFED 1.3 support * wacom driver to add
support for Cintiq 20WSX, Wacom Intuos3 12x19, 12x12 and 4x6 tablets *
sata_svw driver to support Broadcom HT-1100 chipsets * libata to
un-blacklist Hitachi drives to enable NCQ * ide driver allows command
line option to disable ide drivers * psmouse support for cortps
protocol

These updated packages fix the following security issues :

* NULL pointer access due to missing checks for terminal validity.
(CVE-2008-2812, Moderate)

* a security flaw was found in the Linux kernel Universal Disk Format
file system. (CVE-2006-4145, Low)

For further details, refer to the latest Red Hat Enterprise Linux 4.7
release notes: redhat.com/docs/manuals/enterprise"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-4145.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-2812.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0665.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2008:0665";
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
  if (rpm_check(release:"RHEL4", reference:"kernel-2.6.9-78.EL")) flag++;
  if (rpm_check(release:"RHEL4", reference:"kernel-devel-2.6.9-78.EL")) flag++;
  if (rpm_check(release:"RHEL4", reference:"kernel-doc-2.6.9-78.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-hugemem-2.6.9-78.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-hugemem-devel-2.6.9-78.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-78.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-78.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-smp-2.6.9-78.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-smp-2.6.9-78.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-smp-devel-2.6.9-78.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-78.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-xenU-2.6.9-78.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-xenU-2.6.9-78.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-xenU-devel-2.6.9-78.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-xenU-devel-2.6.9-78.EL")) flag++;

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
