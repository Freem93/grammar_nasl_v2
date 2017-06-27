#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:808 and 
# CentOS Errata and Security Advisory 2005:808 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21967);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/06/28 23:40:40 $");

  script_cve_id("CVE-2005-3053", "CVE-2005-3108", "CVE-2005-3110", "CVE-2005-3119", "CVE-2005-3180", "CVE-2005-3181");
  script_osvdb_id(19734, 19923, 19924, 19925, 19927, 19931, 19932);
  script_xref(name:"RHSA", value:"2005:808");

  script_name(english:"CentOS 4 : kernel (CESA-2005:808)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix several security issues and a page
attribute mapping bug are now available for Red Hat Enterprise Linux
4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

An issue was discovered that affects how page attributes are changed
by the kernel. Video drivers, which sometimes map kernel pages with a
different caching policy than write-back, are now expected to function
correctly. This change affects the x86, AMD64, and Intel EM64T
architectures.

In addition the following security bugs were fixed :

The set_mempolicy system call did not check for negative numbers in
the policy field. An unprivileged local user could use this flaw to
cause a denial of service (system panic). (CVE-2005-3053)

A flaw in ioremap handling on AMD 64 and Intel EM64T systems. An
unprivileged local user could use this flaw to cause a denial of
service or minor information leak. (CVE-2005-3108)

A race condition in the ebtables netfilter module. On a SMP system
that is operating under a heavy load this flaw may allow remote
attackers to cause a denial of service (crash). (CVE-2005-3110)

A memory leak was found in key handling. An unprivileged local user
could use this flaw to cause a denial of service. (CVE-2005-3119)

A flaw in the Orinoco wireless driver. On systems running the
vulnerable drive, a remote attacker could send carefully crafted
packets which would divulge the contents of uninitialized kernel
memory. (CVE-2005-3180)

A memory leak was found in the audit system. An unprivileged local
user could use this flaw to cause a denial of service. (CVE-2005-3181)

All Red Hat Enterprise Linux 4 users are advised to upgrade their
kernels to the packages associated with their machine architectures
and configurations as listed in this erratum."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012342.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f707ab1c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012343.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?94d156ef"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012344.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f85b3a4e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/02");
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
if (rpm_check(release:"CentOS-4", reference:"kernel-2.6.9-22.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kernel-devel-2.6.9-22.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-doc-2.6.9-22.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-doc-2.6.9-22.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-2.6.9-22.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-22.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-2.6.9-22.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-2.6.9-22.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-devel-2.6.9-22.0.1.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-22.0.1.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
