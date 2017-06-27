#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0779 and 
# CentOS Errata and Security Advisory 2010:0779 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(50790);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/04 14:30:42 $");

  script_cve_id("CVE-2010-2942", "CVE-2010-3067", "CVE-2010-3477");
  script_bugtraq_id(42529, 43353);
  script_osvdb_id(68177);
  script_xref(name:"RHSA", value:"2010:0779");

  script_name(english:"CentOS 4 : kernel (CESA-2010:0779)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* Information leak flaws were found in the Linux kernel Traffic
Control Unit implementation. A local attacker could use these flaws to
cause the kernel to leak kernel memory to user-space, possibly leading
to the disclosure of sensitive information. (CVE-2010-2942, Moderate)

* A flaw was found in the tcf_act_police_dump() function in the Linux
kernel network traffic policing implementation. A data structure in
tcf_act_police_dump() was not initialized properly before being copied
to user-space. A local, unprivileged user could use this flaw to cause
an information leak. (CVE-2010-3477, Moderate)

* A missing upper bound integer check was found in the sys_io_submit()
function in the Linux kernel asynchronous I/O implementation. A local,
unprivileged user could use this flaw to cause an information leak.
(CVE-2010-3067, Low)

Red Hat would like to thank Tavis Ormandy for reporting CVE-2010-3067.

This update also fixes the following bugs :

* When two systems using bonding devices in the adaptive load
balancing (ALB) mode communicated with each other, an endless loop of
ARP replies started between these two systems due to a faulty MAC
address update. With this update, the MAC address update no longer
creates unneeded ARP replies. (BZ#629239)

* When running the Connectathon NFS Testsuite with certain clients and
Red Hat Enterprise Linux 4.8 as the server, nfsvers4, lock, and test2
failed the Connectathon test. (BZ#625535)

* For UDP/UNIX domain sockets, due to insufficient memory barriers in
the network code, a process sleeping in select() may have missed
notifications about new data. In rare cases, this bug may have caused
a process to sleep forever. (BZ#640117)

* In certain situations, a bug found in either the HTB or TBF network
packet schedulers in the Linux kernel could have caused a kernel panic
when using Broadcom network cards with the bnx2 driver. (BZ#624363)

* Previously, allocating fallback cqr for DASD reserve/release IOCTLs
failed because it used the memory pool of the respective device. This
update preallocates sufficient memory for a single reserve/release
request. (BZ#626828)

* In some situations a bug prevented 'force online' succeeding for a
DASD device. (BZ#626827)

* Using the 'fsstress' utility may have caused a kernel panic.
(BZ#633968)

* This update introduces additional stack guard patches. (BZ#632515)

* A bug was found in the way the megaraid_sas driver handled physical
disks and management IOCTLs. All physical disks were exported to the
disk layer, allowing an oops in megasas_complete_cmd_dpc() when
completing the IOCTL command if a timeout occurred. (BZ#631903)

* Previously, a warning message was returned when a large amount of
messages was passed through netconsole and a considerable amount of
network load was added. With this update, the warning message is no
longer displayed. (BZ#637729)

* Executing a large 'dd' command (1 to 5GB) on an iSCSI device with
the qla3xxx driver caused a system crash due to the incorrect storing
of a private data structure. With this update, the size of the stored
data structure is checked and the system crashes no longer occur.
(BZ#624364)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-October/017107.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?511738e3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-October/017108.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c7b1377a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xenU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xenU-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-devel-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-devel-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-doc-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-doc-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-devel-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-xenU-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-xenU-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-xenU-devel-2.6.9-89.31.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-xenU-devel-2.6.9-89.31.1.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
