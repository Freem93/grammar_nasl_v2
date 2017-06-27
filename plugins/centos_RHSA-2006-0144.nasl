#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0144 and 
# CentOS Errata and Security Advisory 2006:0144 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21882);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2005-2458", "CVE-2005-2801", "CVE-2005-3276", "CVE-2005-4798");
  script_osvdb_id(19026, 19314, 21281);
  script_xref(name:"RHSA", value:"2006:0144");

  script_name(english:"CentOS 3 : kernel (CESA-2006:0144)");
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
seventh regular update.

This security advisory has been rated as having moderate security
impact by the Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

This is the seventh regular kernel update to Red Hat Enterprise Linux
3.

New features introduced by this update include :

  - addition of the bnx2, dell_rbu, and megaraid_sas device
    drivers - support for multi-core, multi-threaded Intel
    Itanium processors - upgrade of the SATA subsystem to
    include ATAPI and SMART support - optional tuning via
    the new numa_memory_allocator, arp_announce, and
    printk_ratelimit sysctls

There were many bug fixes in various parts of the kernel. The ongoing
effort to resolve these problems has resulted in a marked improvement
in the reliability and scalability of Red Hat Enterprise Linux 3.

There were numerous driver updates and security fixes (elaborated
below). Other key areas affected by fixes in this update include the
networking subsystem, the VM subsystem, NPTL handling, autofs4, the
USB subsystem, CPU enumeration, and 32-bit-exec-mode handling on
64-bit architectures.

The following device drivers have been upgraded to new versions :

aacraid -------- 1.1.5-2412 bnx2 ----------- 1.4.30 (new) dell_rbu
------- 2.1 (new) e1000 ---------- 6.1.16-k3 emulex --------- 7.3.3
fusion --------- 2.06.16.02 ipmi ----------- 35.11 megaraid2 ------
v2.10.10.1 megaraid_sas --- 00.00.02.00 (new) tg3 ------------ 3.43RH

The following security bugs were fixed in this update :

  - a flaw in gzip/zlib handling internal to the kernel that
    allowed a local user to cause a denial of service
    (crash) (CVE-2005-2458,low)

  - a flaw in ext3 EA/ACL handling of attribute sharing that
    allowed a local user to gain privileges (CVE-2005-2801,
    moderate)

  - a minor info leak with the get_thread_area() syscall
    that allowed a local user to view uninitialized kernel
    stack data (CVE-2005-3276, low)

Note: The kernel-unsupported package contains various drivers and
modules that are unsupported and therefore might contain security
problems that have not been addressed.

All Red Hat Enterprise Linux 3 users are advised to upgrade their
kernels to the packages associated with their machine architectures
and configurations as listed in this erratum."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-March/012746.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c277c050"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-March/012747.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71af61f1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-March/012755.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?40f2b73a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/24");
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
if (rpm_check(release:"CentOS-3", reference:"kernel-2.4.21-40.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-BOOT-2.4.21-40.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-doc-2.4.21-40.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-hugemem-2.4.21-40.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-hugemem-unsupported-2.4.21-40.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-smp-2.4.21-40.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-smp-2.4.21-40.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-smp-unsupported-2.4.21-40.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-smp-unsupported-2.4.21-40.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-source-2.4.21-40.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-unsupported-2.4.21-40.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
