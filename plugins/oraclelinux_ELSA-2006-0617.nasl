#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisories ELSA-2006-0617 / 
# ELSA-2006-0689.
#

include("compat.inc");

if (description)
{
  script_id(67401);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/07 20:46:55 $");

  script_cve_id("CVE-2004-2660", "CVE-2005-4811", "CVE-2006-0039", "CVE-2006-1858", "CVE-2006-2071", "CVE-2006-2444", "CVE-2006-2932", "CVE-2006-2935", "CVE-2006-2936", "CVE-2006-3468", "CVE-2006-3626", "CVE-2006-3741", "CVE-2006-3745", "CVE-2006-4093", "CVE-2006-4535", "CVE-2006-4623", "CVE-2006-4997");
  script_osvdb_id(25139, 25696, 25697, 25750, 26552, 27119, 27120, 27540, 27812, 28034, 28119, 28120, 28718, 28937, 29538, 29539, 29540);
  script_xref(name:"RHSA", value:"2006:0617");
  script_xref(name:"RHSA", value:"2006:0689");

  script_name(english:"Oracle Linux 4 : kernel (ELSA-2006-0617 / ELSA-2006-0689)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix security issues are now available. 

This update has been rated as having important security impact by the
Red Hat Security Response Team. 

The Linux kernel handles the basic functions of the operating system. 

These new kernel packages contain fixes for the security issues
described below :


From Red Hat Security Advisory 2006-0617 :

* a flaw in the proc file system that allowed a local user to use a
suid-wrapper for scripts to gain root privileges (CVE-2006-3626,
Important)

* a flaw in the SCTP implementation that allowed a local user to cause
a denial of service (panic) or to possibly gain root privileges
(CVE-2006-3745, Important)

* a flaw in NFS exported ext2/ext3 partitions when handling invalid
inodes that allowed a remote authenticated user to cause a denial of
service (filesystem panic) (CVE-2006-3468, Important)

* a flaw in the restore_all code path of the 4/4GB split support of
non-hugemem kernels that allowed a local user to cause a denial of
service (panic) (CVE-2006-2932, Important)

* a flaw in IPv4 netfilter handling for the unlikely use of SNMP NAT
processing that allowed a remote user to cause a denial of service
(crash) or potential memory corruption (CVE-2006-2444, Moderate)

* a flaw in the DVD handling of the CDROM driver that could be used
together with a custom built USB device to gain root privileges
(CVE-2006-2935, Moderate)

* a flaw in the handling of O_DIRECT writes that allowed a local user
to cause a denial of service (memory consumption) (CVE-2004-2660, Low)

* a flaw in the SCTP chunk length handling that allowed a remote user
to cause a denial of service (crash) (CVE-2006-1858, Low)

* a flaw in the input handling of the ftdi_sio driver that allowed a
local user to cause a denial of service (memory consumption)
(CVE-2006-2936, Low)

In addition a bugfix was added to enable a clean reboot for the IBM
Pizzaro machines.

Red Hat would like to thank Wei Wang of McAfee Avert Labs and Kirill
Korotaev for reporting issues fixed in this erratum.


From Red Hat Security Advisory ELSA-2006-0689 :

* a flaw in the SCTP support that allowed a local user to cause a
denial of service (crash) with a specific SO_LINGER value.
(CVE-2006-4535, Important)

* a flaw in the hugepage table support that allowed a local user to
cause a denial of service (crash). (CVE-2005-4811, Important)

* a flaw in the mprotect system call that allowed setting write
permission for a read-only attachment of shared memory.
(CVE-2006-2071, Moderate)

* a flaw in HID0[31] (en_attn) register handling on PowerPC 970
systems that allowed a local user to cause a denial of service.
(crash) (CVE-2006-4093, Moderate)

* a flaw in the perfmon support of Itanium systems that allowed a
local user to cause a denial of service by consuming all file
descriptors. (CVE-2006-3741, Moderate)

* a flaw in the ATM subsystem. On systems with installed ATM hardware
and configured ATM support, a remote user could cause a denial of
service (panic) by accessing socket buffers memory after freeing them.
(CVE-2006-4997, Moderate)

* a flaw in the DVB subsystem. On systems with installed DVB hardware
and configured DVB support, a remote user could cause a denial of
service (panic) by sending a ULE SNDU packet with length of 0.
(CVE-2006-4623, Low)

* an information leak in the network subsystem that possibly allowed a
local user to read sensitive data from kernel memory. (CVE-2006-0039,
Low)

In addition, two bugfixes for the IPW-2200 wireless driver were
included. The first one ensures that wireless management applications
correctly identify IPW-2200 controlled devices, while the second fix
ensures that DHCP requests using the IPW-2200 operate correctly.

Red Hat would like to thank Olof Johansson, Stephane Eranian and Solar
Designer for reporting issues fixed in this erratum."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2006-November/000011.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 362);

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-largesmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-largesmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);


flag = 0;
if (rpm_check(release:"EL4", cpu:"i386", reference:"kernel-2.6.9-42.0.3.0.2.EL")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-2.6.9-42.0.3.0.2.EL")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"kernel-devel-2.6.9-42.0.3.0.2.EL")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-devel-2.6.9-42.0.3.0.2.EL")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-42.0.3.0.2.EL")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-42.0.3.0.2.EL")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-42.0.3.0.2.EL")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-42.0.3.0.2.EL")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"kernel-smp-2.6.9-42.0.3.0.2.EL")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-smp-2.6.9-42.0.3.0.2.EL")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"kernel-smp-devel-2.6.9-42.0.3.0.2.EL")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-42.0.3.0.2.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

