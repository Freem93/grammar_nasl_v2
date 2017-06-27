#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0938 and 
# CentOS Errata and Security Advisory 2007:0938 respectively.
#

include("compat.inc");

if (description)
{
  script_id(26207);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/04 14:30:41 $");

  script_cve_id("CVE-2007-4573");
  script_bugtraq_id(25774);
  script_xref(name:"RHSA", value:"2007:0938");

  script_name(english:"CentOS 3 : kernel (CESA-2007:0938)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix a security issue in the Red Hat
Enterprise Linux 3 kernel are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

A flaw was found in ia32 emulation affecting users running 64-bit
versions of Red Hat Enterprise Linux on x86_64 architectures. A local
user could use this flaw to gain elevated privileges. (CVE-2007-4573).

Red Hat would like to thank Wojciech Purczynski for reporting this
issue.

Red Hat Enterprise Linux 3 users are advised to upgrade to these
packages, which contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014247.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa8ae94a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014248.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0b17fcde"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014249.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b9d6f4b8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014250.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?70bc98a0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/03");
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
if (rpm_check(release:"CentOS-3", reference:"kernel-2.4.21-52.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-BOOT-2.4.21-52.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-doc-2.4.21-52.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-hugemem-2.4.21-52.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-hugemem-unsupported-2.4.21-52.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-smp-2.4.21-52.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-smp-2.4.21-52.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-smp-unsupported-2.4.21-52.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-smp-unsupported-2.4.21-52.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-source-2.4.21-52.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-unsupported-2.4.21-52.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
