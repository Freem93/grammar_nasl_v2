#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0617 and 
# CentOS Errata and Security Advisory 2006:0617 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(22279);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:25:26 $");

  script_cve_id("CVE-2004-2660", "CVE-2006-1858", "CVE-2006-2444", "CVE-2006-2932", "CVE-2006-2935", "CVE-2006-2936", "CVE-2006-3468", "CVE-2006-3626", "CVE-2006-3745");
  script_osvdb_id(25696, 25750, 26552, 27119, 27120, 27540, 27812, 28119, 28120);
  script_xref(name:"RHSA", value:"2006:0617");

  script_name(english:"CentOS 4 : kernel (CESA-2006:0617)");
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

All Red Hat Enterprise Linux 4 users are advised to upgrade their
kernels to the packages associated with their machine architectures
and configurations as listed in this erratum."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013149.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e946dff9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013150.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?63502ea3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013190.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?946a129a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20);

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
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/27");
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
if (rpm_check(release:"CentOS-4", reference:"kernel-2.6.9-42.0.2.EL")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kernel-devel-2.6.9-42.0.2.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-doc-2.6.9-42.0.2.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-doc-2.6.9-42.0.2.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-2.6.9-42.0.2.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-42.0.2.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"kernel-largesmp-2.6.9-42.0.2.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-42.0.2.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"kernel-largesmp-devel-2.6.9-42.0.2.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-42.0.2.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-2.6.9-42.0.2.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-2.6.9-42.0.2.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-devel-2.6.9-42.0.2.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-42.0.2.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
