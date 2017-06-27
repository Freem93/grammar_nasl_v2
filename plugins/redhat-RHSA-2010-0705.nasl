#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0705. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63953);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2017/01/10 18:05:23 $");

  script_cve_id("CVE-2010-3081", "CVE-2010-3301");
  script_bugtraq_id(43239);
  script_xref(name:"RHSA", value:"2010:0705");

  script_name(english:"RHEL 5 : kernel (RHSA-2010:0705)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.4 Extended Update Support.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issue :

* The compat_alloc_user_space() function in the Linux kernel 32/64-bit
compatibility layer implementation was missing sanity checks. This
function could be abused in other areas of the Linux kernel if its
length argument can be controlled from user-space. On 64-bit systems,
a local, unprivileged user could use this flaw to escalate their
privileges. (CVE-2010-3081, Important)

Red Hat would like to thank Ben Hawkes for reporting this issue.

Red Hat is aware that a public exploit for this issue is available.
Refer to Knowledgebase article DOC-40265 for further details:
https://access.redhat.com/kb/docs/DOC-40265

Users should upgrade to these updated packages, which contain a
backported patch to correct this issue. The system must be rebooted
for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3081.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/kb/docs/DOC-40265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0705.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-2.6.18-164.25.2.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-2.6.18-164.25.2.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-2.6.18-164.25.2.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-PAE-2.6.18-164.25.2.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-PAE-devel-2.6.18-164.25.2.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-debug-2.6.18-164.25.2.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-debug-2.6.18-164.25.2.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-debug-2.6.18-164.25.2.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-debug-devel-2.6.18-164.25.2.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-debug-devel-2.6.18-164.25.2.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-debug-devel-2.6.18-164.25.2.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-devel-2.6.18-164.25.2.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-devel-2.6.18-164.25.2.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-devel-2.6.18-164.25.2.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", reference:"kernel-doc-2.6.18-164.25.2.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i386", reference:"kernel-headers-2.6.18-164.25.2.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-headers-2.6.18-164.25.2.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-headers-2.6.18-164.25.2.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-kdump-2.6.18-164.25.2.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"kernel-kdump-devel-2.6.18-164.25.2.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-xen-2.6.18-164.25.2.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-xen-2.6.18-164.25.2.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kernel-xen-devel-2.6.18-164.25.2.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kernel-xen-devel-2.6.18-164.25.2.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
