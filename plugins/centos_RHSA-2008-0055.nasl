#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0055 and 
# CentOS Errata and Security Advisory 2008:0055 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(30154);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2007-4130", "CVE-2007-5500", "CVE-2007-6063", "CVE-2007-6151", "CVE-2007-6206", "CVE-2007-6694", "CVE-2008-0001");
  script_bugtraq_id(26477, 26605, 26701, 27280, 27497);
  script_osvdb_id(40911, 40913, 40914);
  script_xref(name:"RHSA", value:"2008:0055");

  script_name(english:"CentOS 4 : kernel (CESA-2008:0055)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix several security issues and a bug in
the Red Hat Enterprise Linux 4 kernel are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

These updated kernel packages fix the following security issues :

A flaw was found in the virtual filesystem (VFS). A local unprivileged
user could truncate directories to which they had write permission;
this could render the contents of the directory inaccessible.
(CVE-2008-0001, Important)

A flaw was found in the implementation of ptrace. A local unprivileged
user could trigger this flaw and possibly cause a denial of service
(system hang). (CVE-2007-5500, Important)

A flaw was found in the way the Red Hat Enterprise Linux 4 kernel
handled page faults when a CPU used the NUMA method for accessing
memory on Itanium architectures. A local unprivileged user could
trigger this flaw and cause a denial of service (system panic).
(CVE-2007-4130, Important)

A possible NULL pointer dereference was found in the chrp_show_cpuinfo
function when using the PowerPC architecture. This may have allowed a
local unprivileged user to cause a denial of service (crash).
(CVE-2007-6694, Moderate)

A flaw was found in the way core dump files were created. If a local
user can get a root-owned process to dump a core file into a
directory, which the user has write access to, they could gain read
access to that core file. This could potentially grant unauthorized
access to sensitive information. (CVE-2007-6206, Moderate)

Two buffer overflow flaws were found in the Linux kernel ISDN
subsystem. A local unprivileged user could use these flaws to cause a
denial of service. (CVE-2007-6063, CVE-2007-6151, Moderate)

As well, these updated packages fix the following bug :

* when moving volumes that contain multiple segments, and a mirror
segment is not the first in the mapping table, running the 'pvmove
/dev/[device] /dev/[device]' command caused a kernel panic. A 'kernel:
Unable to handle kernel paging request at virtual address [address]'
error was logged by syslog.

Red Hat Enterprise Linux 4 users are advised to upgrade to these
updated packages, which contain backported patches to resolve these
issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014657.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0172f80b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014658.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d9746471"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014659.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b530c8a9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 20, 119, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"kernel-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kernel-devel-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-doc-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-doc-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"kernel-largesmp-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"kernel-largesmp-devel-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-devel-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-xenU-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-xenU-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-xenU-devel-2.6.9-67.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-xenU-devel-2.6.9-67.0.4.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
