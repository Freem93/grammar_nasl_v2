#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0021. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63871);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/10 18:05:23 $");

  script_cve_id("CVE-2008-5029", "CVE-2008-5079", "CVE-2008-5182", "CVE-2008-5300");
  script_xref(name:"RHSA", value:"2009:0021");

  script_name(english:"RHEL 5 : kernel (RHSA-2009:0021)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that resolve several security issues are now
available for Red Hat Enterprise Linux 5.2 Extended Update Support.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update includes backported fixes for four security issues. These
issues only affected users of Red Hat Enterprise Linux 5.2 Extended
Update Support as they have already been addressed for users of Red
Hat Enterprise Linux 5 in the 5.3 update, RHSA-2009:0225.

In accordance with the support policy, future security updates to Red
Hat Enterprise Linux 5.2 Extended Update Support will only include
issues of critical security impact.

* when fput() was called to close a socket, the __scm_destroy()
function in the Linux kernel could make indirect recursive calls to
itself. This could, potentially, lead to a denial of service issue.
(CVE-2008-5029, Important)

* the sendmsg() function in the Linux kernel did not block during UNIX
socket garbage collection. This could, potentially, lead to a local
denial of service. (CVE-2008-5300, Important)

* a flaw was found in the Asynchronous Transfer Mode (ATM) subsystem.
A local, unprivileged user could use the flaw to listen on the same
socket more than once, possibly causing a denial of service.
(CVE-2008-5079, Important)

* a race condition was found in the Linux kernel 'inotify' watch
removal and umount implementation. This could allow a local,
unprivileged user to cause a privilege escalation or a denial of
service. (CVE-2008-5182, Important)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. Note: for this update to
take effect, the system must be rebooted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-5029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-5079.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-5182.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-5300.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-0021.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(362, 399);

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/24");
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
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i686", reference:"kernel-2.6.18-92.1.24.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"s390x", reference:"kernel-2.6.18-92.1.24.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"x86_64", reference:"kernel-2.6.18-92.1.24.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i686", reference:"kernel-PAE-2.6.18-92.1.24.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i686", reference:"kernel-PAE-devel-2.6.18-92.1.24.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i686", reference:"kernel-debug-2.6.18-92.1.24.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"s390x", reference:"kernel-debug-2.6.18-92.1.24.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"x86_64", reference:"kernel-debug-2.6.18-92.1.24.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i686", reference:"kernel-debug-devel-2.6.18-92.1.24.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"s390x", reference:"kernel-debug-devel-2.6.18-92.1.24.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"x86_64", reference:"kernel-debug-devel-2.6.18-92.1.24.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i686", reference:"kernel-devel-2.6.18-92.1.24.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"s390x", reference:"kernel-devel-2.6.18-92.1.24.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"x86_64", reference:"kernel-devel-2.6.18-92.1.24.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", reference:"kernel-doc-2.6.18-92.1.24.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i386", reference:"kernel-headers-2.6.18-92.1.24.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"s390x", reference:"kernel-headers-2.6.18-92.1.24.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"x86_64", reference:"kernel-headers-2.6.18-92.1.24.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"s390x", reference:"kernel-kdump-2.6.18-92.1.24.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"s390x", reference:"kernel-kdump-devel-2.6.18-92.1.24.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i686", reference:"kernel-xen-2.6.18-92.1.24.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"x86_64", reference:"kernel-xen-2.6.18-92.1.24.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i686", reference:"kernel-xen-devel-2.6.18-92.1.24.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"x86_64", reference:"kernel-xen-devel-2.6.18-92.1.24.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
