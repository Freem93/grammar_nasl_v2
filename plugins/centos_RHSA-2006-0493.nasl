#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0493 and 
# CentOS Errata and Security Advisory 2006:0493 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21997);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/06/28 23:40:41 $");

  script_cve_id("CVE-2005-2973", "CVE-2005-3272", "CVE-2005-3359", "CVE-2006-0555", "CVE-2006-0741", "CVE-2006-0744", "CVE-2006-1522", "CVE-2006-1525", "CVE-2006-1527", "CVE-2006-1528", "CVE-2006-1855", "CVE-2006-1856", "CVE-2006-1862", "CVE-2006-1864", "CVE-2006-2271", "CVE-2006-2272", "CVE-2006-2274");
  script_osvdb_id(20163, 21278, 23605, 23607, 23893, 24507, 24639, 24715, 25067, 25229, 25632, 25633, 25744, 25745, 25746, 25747, 31663);
  script_xref(name:"RHSA", value:"2006:0493");

  script_name(english:"CentOS 4 : kernel (CESA-2006:0493)");
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

* a flaw in the IPv6 implementation that allowed a local user to cause
a denial of service (infinite loop and crash) (CVE-2005-2973,
important)

* a flaw in the bridge implementation that allowed a remote user to
cause forwarding of spoofed packets via poisoning of the forwarding
table with already dropped frames (CVE-2005-3272, moderate)

* a flaw in the atm module that allowed a local user to cause a denial
of service (panic) via certain socket calls (CVE-2005-3359, important)

* a flaw in the NFS client implementation that allowed a local user to
cause a denial of service (panic) via O_DIRECT writes (CVE-2006-0555,
important)

* a difference in 'sysretq' operation of EM64T (as opposed to Opteron)
processors that allowed a local user to cause a denial of service
(crash) upon return from certain system calls (CVE-2006-0741 and
CVE-2006-0744, important)

* a flaw in the keyring implementation that allowed a local user to
cause a denial of service (OOPS) (CVE-2006-1522, important)

* a flaw in IP routing implementation that allowed a local user to
cause a denial of service (panic) via a request for a route for a
multicast IP (CVE-2006-1525, important)

* a flaw in the SCTP-netfilter implementation that allowed a remote
user to cause a denial of service (infinite loop) (CVE-2006-1527,
important)

* a flaw in the sg driver that allowed a local user to cause a denial
of service (crash) via a dio transfer to memory mapped (mmap) IO space
(CVE-2006-1528, important)

* a flaw in the threading implementation that allowed a local user to
cause a denial of service (panic) (CVE-2006-1855, important)

* two missing LSM hooks that allowed a local user to bypass the LSM by
using readv() or writev() (CVE-2006-1856, moderate)

* a flaw in the virtual memory implementation that allowed local user
to cause a denial of service (panic) by using the lsof command
(CVE-2006-1862, important)

* a directory traversal vulnerability in smbfs that allowed a local
user to escape chroot restrictions for an SMB-mounted filesystem via
'..\\' sequences (CVE-2006-1864, moderate)

* a flaw in the ECNE chunk handling of SCTP that allowed a remote user
to cause a denial of service (panic) (CVE-2006-2271, moderate)

* a flaw in the handling of COOKIE_ECHO and HEARTBEAT control chunks
of SCTP that allowed a remote user to cause a denial of service
(panic) (CVE-2006-2272, moderate)

* a flaw in the handling of DATA fragments of SCTP that allowed a
remote user to cause a denial of service (infinite recursion and
crash) (CVE-2006-2274, moderate)

All Red Hat Enterprise Linux 4 users are advised to upgrade their
kernels to the packages associated with their machine architectures
and configurations as listed in this erratum."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2006-May/012919.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2006-May/012923.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2006-May/012924.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"kernel-2.6.9-34.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kernel-devel-2.6.9-34.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-doc-2.6.9-34.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-doc-2.6.9-34.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-2.6.9-34.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-34.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"kernel-largesmp-2.6.9-34.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-34.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"kernel-largesmp-devel-2.6.9-34.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-34.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-2.6.9-34.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-2.6.9-34.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-devel-2.6.9-34.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-34.0.1.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
