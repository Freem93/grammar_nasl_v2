#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0014 and 
# CentOS Errata and Security Advisory 2007:0014 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(36838);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/03/19 14:21:01 $");

  script_cve_id("CVE-2006-4538", "CVE-2006-4813", "CVE-2006-4814", "CVE-2006-5174", "CVE-2006-5619", "CVE-2006-5751", "CVE-2006-5753", "CVE-2006-5754", "CVE-2006-5757", "CVE-2006-5823", "CVE-2006-6053", "CVE-2006-6054", "CVE-2006-6056", "CVE-2006-6106", "CVE-2006-6535");
  script_bugtraq_id(19702, 20379, 20920, 21353, 21522, 21604, 21663, 22316);
  script_osvdb_id(28936, 29537, 30002, 30067, 30215, 30293, 30295, 30297, 30725, 31375, 31376, 31377, 33020, 33029, 33030);
  script_xref(name:"RHSA", value:"2007:0014");

  script_name(english:"CentOS 4 : kernel (CESA-2007:0014)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix several security issues in the Red
Hat Enterprise Linux 4 kernel are now available.

This security advisory has been rated as having important security
impact by the Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

These new kernel packages contain fixes for the security issues
described below :

* a flaw in the get_fdb_entries function of the network bridging
support that allowed a local user to cause a denial of service (crash)
or allow a potential privilege escalation (CVE-2006-5751, Important)

* an information leak in the _block_prepare_write function that
allowed a local user to read kernel memory (CVE-2006-4813, Important)

* an information leak in the copy_from_user() implementation on s390
and s390x platforms that allowed a local user to read kernel memory
(CVE-2006-5174, Important)

* a flaw in the handling of /proc/net/ip6_flowlabel that allowed a
local user to cause a denial of service (infinite loop)
(CVE-2006-5619, Important)

* a flaw in the AIO handling that allowed a local user to cause a
denial of service (panic) (CVE-2006-5754, Important)

* a race condition in the mincore system core that allowed a local
user to cause a denial of service (system hang) (CVE-2006-4814,
Moderate)

* a flaw in the ELF handling on ia64 and sparc architectures which
triggered a cross-region memory mapping and allowed a local user to
cause a denial of service (CVE-2006-4538, Moderate)

* a flaw in the dev_queue_xmit function of the network subsystem that
allowed a local user to cause a denial of service (data corruption)
(CVE-2006-6535, Moderate)

* a flaw in the handling of CAPI messages over Bluetooth that allowed
a remote system to cause a denial of service or potential code
execution. This flaw is only exploitable if a privileged user
establishes a connection to a malicious remote device (CVE-2006-6106,
Moderate)

* a flaw in the listxattr system call that allowed a local user to
cause a denial of service (data corruption) or potential privilege
escalation. To successfully exploit this flaw the existence of a bad
inode is required first (CVE-2006-5753, Moderate)

* a flaw in the __find_get_block_slow function that allowed a local
privileged user to cause a denial of service (CVE-2006-5757, Low)

* various flaws in the supported filesystems that allowed a local
privileged user to cause a denial of service (CVE-2006-5823,
CVE-2006-6053, CVE-2006-6054, CVE-2006-6056, Low)

In addition to the security issues described above, fixes for the
following bugs were included :

* initialization error of the tg3 driver with some BCM5703x network
card

* a memory leak in the audit subsystem

* x86_64 nmi watchdog timeout is too short

* ext2/3 directory reads fail intermittently

Red Hat would like to thank Dmitriy Monakhov and Kostantin Khorenko
for reporting issues fixed in this erratum.

All Red Hat Enterprise Linux 4 users are advised to upgrade their
kernels to the packages associated with their machine architecture and
configurations as listed in this erratum."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-January/013485.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b14dac88"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-January/013486.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8acb144f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-January/013494.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0f23e804"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"kernel-2.6.9-42.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kernel-devel-2.6.9-42.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-doc-2.6.9-42.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-doc-2.6.9-42.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-2.6.9-42.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-42.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"kernel-largesmp-2.6.9-42.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-42.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"kernel-largesmp-devel-2.6.9-42.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-42.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-2.6.9-42.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-2.6.9-42.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-devel-2.6.9-42.0.8.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-42.0.8.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
