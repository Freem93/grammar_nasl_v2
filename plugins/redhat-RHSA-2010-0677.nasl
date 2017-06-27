#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0677. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63952);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/13 15:17:27 $");

  script_cve_id("CVE-2010-2240");
  script_bugtraq_id(42505);
  script_xref(name:"RHSA", value:"2010:0677");

  script_name(english:"RHEL 4 : kernel (RHSA-2010:0677)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix one security issue are now available
for Red Hat Enterprise Linux 4.7 Extended Update Support.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issue :

* When an application has a stack overflow, the stack could silently
overwrite another memory mapped area instead of a segmentation fault
occurring, which could cause an application to execute arbitrary code,
possibly leading to privilege escalation. It is known that the X
Window System server can be used to trigger this flaw. (CVE-2010-2240,
Important)

Red Hat would like to thank the X.Org security team for reporting this
issue. Upstream acknowledges Rafal Wojtczuk as the original reporter.

Users should upgrade to these updated packages, which contain
backported patches to correct this issue. The system must be rebooted
for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-2240.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0677.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-largesmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-largesmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xenU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xenU-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.7");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL4", sp:"7", reference:"kernel-2.6.9-78.0.32.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", reference:"kernel-devel-2.6.9-78.0.32.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", reference:"kernel-doc-2.6.9-78.0.32.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"i686", reference:"kernel-hugemem-2.6.9-78.0.32.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"i686", reference:"kernel-hugemem-devel-2.6.9-78.0.32.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-78.0.32.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-78.0.32.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"i686", reference:"kernel-smp-2.6.9-78.0.32.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"x86_64", reference:"kernel-smp-2.6.9-78.0.32.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"i686", reference:"kernel-smp-devel-2.6.9-78.0.32.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-78.0.32.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"i686", reference:"kernel-xenU-2.6.9-78.0.32.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"x86_64", reference:"kernel-xenU-2.6.9-78.0.32.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"i686", reference:"kernel-xenU-devel-2.6.9-78.0.32.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"x86_64", reference:"kernel-xenU-devel-2.6.9-78.0.32.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
