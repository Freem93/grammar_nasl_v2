#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0940 and 
# CentOS Errata and Security Advisory 2007:0940 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43654);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2007-3105", "CVE-2007-3380", "CVE-2007-3513", "CVE-2007-3731", "CVE-2007-3848", "CVE-2007-3850", "CVE-2007-4133", "CVE-2007-4308", "CVE-2007-4574");
  script_bugtraq_id(24734, 25216, 25348, 25387);
  script_osvdb_id(37109, 37116, 37122, 37286, 37288, 37289, 39239, 45488, 45489);
  script_xref(name:"RHSA", value:"2007:0940");

  script_name(english:"CentOS 5 : kernel (CESA-2007:0940)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix various security issues in the Red
Hat Enterprise Linux 5 kernel are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

These new kernel packages contain fixes for the following security
issues :

* A flaw was found in the backported stack unwinder fixes in Red Hat
Enterprise Linux 5. On AMD64 and Intel 64 platforms, a local user
could trigger this flaw and cause a denial of service. (CVE-2007-4574,
Important)

* A flaw was found in the handling of process death signals. This
allowed a local user to send arbitrary signals to the suid-process
executed by that user. A successful exploitation of this flaw depends
on the structure of the suid-program and its signal handling.
(CVE-2007-3848, Important)

* A flaw was found in the Distributed Lock Manager (DLM) in the
cluster manager. This allowed a remote user who is able to connect to
the DLM port to cause a denial of service. (CVE-2007-3380, Important)

* A flaw was found in the aacraid SCSI driver. This allowed a local
user to make ioctl calls to the driver which should otherwise be
restricted to privileged users. (CVE-2007-4308, Moderate)

* A flaw was found in the prio_tree handling of the hugetlb support
that allowed a local user to cause a denial of service. This only
affected kernels with hugetlb support. (CVE-2007-4133, Moderate)

* A flaw was found in the eHCA driver on PowerPC architectures that
allowed a local user to access 60k of physical address space. This
address space could contain sensitive information. (CVE-2007-3850,
Moderate)

* A flaw was found in ptrace support that allowed a local user to
cause a denial of service via a NULL pointer dereference.
(CVE-2007-3731, Moderate)

* A flaw was found in the usblcd driver that allowed a local user to
cause a denial of service by writing data to the device node. To
exploit this issue, write access to the device node was needed.
(CVE-2007-3513, Moderate)

* A flaw was found in the random number generator implementation that
allowed a local user to cause a denial of service or possibly gain
privileges. If the root user raised the default wakeup threshold over
the size of the output pool, this flaw could be exploited.
(CVE-2007-3105, Low)

In addition to the security issues described above, several bug fixes
preventing possible system crashes and data corruption were also
included.

Red Hat Enterprise Linux 5 users are advised to upgrade to these
packages, which contain backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-October/014334.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?827606bf"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-October/014335.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a1be4d9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 20, 119, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/08");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-8.1.15.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-8.1.15.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-8.1.15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-8.1.15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-8.1.15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-8.1.15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-8.1.15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-8.1.15.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
