#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0437 and 
# CentOS Errata and Security Advisory 2006:0437 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(22135);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2005-3055", "CVE-2005-3107", "CVE-2006-0741", "CVE-2006-0742", "CVE-2006-0744", "CVE-2006-1056", "CVE-2006-1242", "CVE-2006-1343", "CVE-2006-2444");
  script_bugtraq_id(17600, 18081);
  script_osvdb_id(19702, 19929, 23607, 23660, 24071, 24137, 24639, 24746, 24807, 25750);
  script_xref(name:"RHSA", value:"2006:0437");

  script_name(english:"CentOS 3 : kernel (CESA-2006:0437)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages are now available as part of ongoing support
and maintenance of Red Hat Enterprise Linux version 3. This is the
eighth regular update.

This security advisory has been rated as having important security
impact by the Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

This is the eighth regular kernel update to Red Hat Enterprise Linux
3.

New features introduced by this update include :

  - addition of the adp94xx and dcdbas device drivers -
    diskdump support on megaraid_sas, qlogic, and swap
    partitions - support for new hardware via driver and
    SCSI white-list updates

There were many bug fixes in various parts of the kernel. The ongoing
effort to resolve these problems has resulted in a marked improvement
in the reliability and scalability of Red Hat Enterprise Linux 3.

There were numerous driver updates and security fixes (elaborated
below). Other key areas affected by fixes in this update include the
networking subsystem, the NFS and autofs4 file systems, the SCSI and
USB subsystems, and architecture-specific handling affecting AMD
Opteron and Intel EM64T processors.

The following device drivers have been added or upgraded to new
versions :

adp94xx -------- 1.0.8 (new) bnx2 ----------- 1.4.38 cciss ----------
2.4.60.RH1 dcdbas --------- 5.6.0-1 (new) e1000 ---------- 7.0.33-k2
emulex --------- 7.3.6 forcedeth ------ 0.30 ipmi ----------- 35.13
qlogic --------- 7.07.04b6 tg3 ------------ 3.52RH

The following security bugs were fixed in this update :

  - a flaw in the USB devio handling of device removal that
    allowed a local user to cause a denial of service
    (crash) (CVE-2005-3055, moderate)

  - a flaw in the exec() handling of multi-threaded tasks
    using ptrace() that allowed a local user to cause a
    denial of service (hang of a user process)
    (CVE-2005-3107, low)

  - a difference in 'sysretq' operation of EM64T (as opposed
    to Opteron) processors that allowed a local user to
    cause a denial of service (crash) upon return from
    certain system calls (CVE-2006-0741 and CVE-2006-0744,
    important)

  - a flaw in unaligned accesses handling on Intel Itanium
    processors that allowed a local user to cause a denial
    of service (crash) (CVE-2006-0742, important)

  - an info leak on AMD-based x86 and x86_64 systems that
    allowed a local user to retrieve the floating point
    exception state of a process run by a different user
    (CVE-2006-1056, important)

  - a flaw in IPv4 packet output handling that allowed a
    remote user to bypass the zero IP ID countermeasure on
    systems with a disabled firewall (CVE-2006-1242, low)

  - a minor info leak in socket option handling in the
    network code (CVE-2006-1343, low)

  - a flaw in IPv4 netfilter handling for the unlikely use
    of SNMP NAT processing that allowed a remote user to
    cause a denial of service (crash) or potential memory
    corruption (CVE-2006-2444, moderate)

Note: The kernel-unsupported package contains various drivers and
modules that are unsupported and therefore might contain security
problems that have not been addressed.

All Red Hat Enterprise Linux 3 users are advised to upgrade their
kernels to the packages associated with their machine architectures
and configurations as listed in this erratum."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013097.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?be96809b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013098.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?231155c5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013053.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b692243"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-BOOT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem-unsupported");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp-unsupported");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-unsupported");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/25");
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
if (rpm_check(release:"CentOS-3", reference:"kernel-2.4.21-47.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-BOOT-2.4.21-47.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-doc-2.4.21-47.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-hugemem-2.4.21-47.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-hugemem-unsupported-2.4.21-47.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-smp-2.4.21-47.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-smp-2.4.21-47.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-smp-unsupported-2.4.21-47.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-smp-unsupported-2.4.21-47.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-source-2.4.21-47.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-unsupported-2.4.21-47.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
