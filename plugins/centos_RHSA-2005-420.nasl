#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:420 and 
# CentOS Errata and Security Advisory 2005:420 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21937);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-0136", "CVE-2005-0209", "CVE-2005-0937", "CVE-2005-1264", "CVE-2005-3107");
  script_osvdb_id(16609, 17235);
  script_xref(name:"RHSA", value:"2005:420");

  script_name(english:"CentOS 4 : kernel (CESA-2005:420)");
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
first regular update.

[Updated 9 August 2005] The advisory text has been updated to show
that this update also contained fixes for the security issues named
CVE-2005-0209 and CVE-2005-0937. No changes have been made to the
packages associated with this advisory.

The Linux kernel handles the basic functions of the operating system.

This is the first regular kernel update to Red Hat Enterprise Linux 4.

A flaw affecting the auditing code was discovered. On Itanium
architectures a local user could use this flaw to cause a denial of
service (crash). This issue is rated as having important security
impact (CVE-2005-0136).

A flaw was discovered in the servicing of a raw device ioctl. A local
user who has access to raw devices could use this flaw to write to
kernel memory and cause a denial of service or potentially gain
privileges. This issue is rated as having moderate security impact
(CVE-2005-1264).

A flaw in fragment forwarding was discovered that affected the
netfilter subsystem for certain network interface cards. A remote
attacker could send a set of bad fragments and cause a denial of
service (system crash). Acenic and SunGEM network interfaces were the
only adapters affected, which are in widespread use. (CVE-2005-0209)

A flaw in the futex functions was discovered affecting the Linux 2.6
kernel. A local user could use this flaw to cause a denial of service
(system crash). (CVE-2005-0937)

New features introduced by this update include: - Fixed TCP BIC
congestion handling. - Diskdump support for more controllers
(megaraid, SATA) - Device mapper multipath support - AMD64 dual core
support. - Intel ICH7 hardware support.

There were many bug fixes in various parts of the kernel. The ongoing
effort to resolve these problems has resulted in a marked improvement
in the reliability and scalability of Red Hat Enterprise Linux 4.

The following device drivers have been upgraded to new versions:
ata_piix -------- 1.03 bonding --------- 2.6.1 e1000 -----------
5.6.10.1-k2-NAPI e100 ------------ 3.3.6-k2-NAPI ibmveth ---------
1.03 libata ---------- 1.02 to 1.10 lpfc ------------ 0:8.0.16 to
0:8.0.16.6_x2 megaraid_mbox --- 2.20.4.0 to 2.20.4.5 megaraid_mm -----
2.20.2.0-rh1 to 2.20.2.5 sata_nv --------- 0.03 to 0.6 sata_promise
---- 1.00 to 1.01 sata_sil -------- 0.8 sata_sis -------- 0.5 sata_svw
-------- 1.05 sata_sx4 -------- 0.7 sata_via -------- 1.0 sata_vsc
-------- 1.0 tg3 ------------- 3.22-rh ipw2100 --------- 1.0.3 ipw2200
--------- 1.0.0

All Red Hat Enterprise Linux 4 users are advised to upgrade their
kernels to the packages associated with their machine architectures
and configurations as listed in this erratum."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011800.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?452f8ce1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011803.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d0267c29"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011808.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bef8b1bd"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-sourcecode");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/16");
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
if (rpm_check(release:"CentOS-4", reference:"kernel-2.6.9-11.EL")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kernel-devel-2.6.9-11.EL")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kernel-doc-2.6.9-11.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-2.6.9-11.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-11.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-2.6.9-11.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-2.6.9-11.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-devel-2.6.9-11.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-11.EL")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kernel-sourcecode-2.6.9-11.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
