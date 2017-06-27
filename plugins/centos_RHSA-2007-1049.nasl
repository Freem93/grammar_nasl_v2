#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:1049 and 
# CentOS Errata and Security Advisory 2007:1049 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(29190);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2006-4538", "CVE-2007-2172", "CVE-2007-3739", "CVE-2007-3848", "CVE-2007-4308");
  script_bugtraq_id(19702, 25216, 25387);
  script_osvdb_id(28936, 37120, 37121, 37122, 37285, 37289);
  script_xref(name:"RHSA", value:"2007:1049");

  script_name(english:"CentOS 3 : kernel (CESA-2007:1049)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix several security issues and a bug in
the Red Hat Enterprise Linux 3 kernel are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

A flaw was found in the handling of process death signals. This
allowed a local user to send arbitrary signals to the suid-process
executed by that user. A successful exploitation of this flaw depends
on the structure of the suid-program and its signal handling.
(CVE-2007-3848, Important)

A flaw was found in the IPv4 forwarding base. This allowed a local
user to cause a denial of service. (CVE-2007-2172, Important)

A flaw was found where a corrupted executable file could cause
cross-region memory mappings on Itanium systems. This allowed a local
user to cause a denial of service. (CVE-2006-4538, Moderate)

A flaw was found in the stack expansion when using the hugetlb kernel
on PowerPC systems. This allowed a local user to cause a denial of
service. (CVE-2007-3739, Moderate)

A flaw was found in the aacraid SCSI driver. This allowed a local user
to make ioctl calls to the driver that should be restricted to
privileged users. (CVE-2007-4308, Moderate)

As well, these updated packages fix the following bug :

* a bug in the TCP header prediction code may have caused 'TCP:
Treason uncloaked!' messages to be logged. In certain situations this
may have lead to TCP connections hanging or aborting.

Red Hat Enterprise Linux 3 users are advised to upgrade to these
updated packages, which contain backported patches to resolve these
issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014479.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ff26ad9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014480.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?53ab71e1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014486.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de12b2f0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 119, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"kernel-2.4.21-53.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-BOOT-2.4.21-53.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-doc-2.4.21-53.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-hugemem-2.4.21-53.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-hugemem-unsupported-2.4.21-53.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-smp-2.4.21-53.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-smp-2.4.21-53.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-smp-unsupported-2.4.21-53.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-smp-unsupported-2.4.21-53.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-source-2.4.21-53.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-unsupported-2.4.21-53.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
