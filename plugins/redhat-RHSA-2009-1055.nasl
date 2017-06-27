#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1055. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63879);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/05/02 17:31:16 $");

  script_cve_id("CVE-2009-0065");
  script_xref(name:"RHSA", value:"2009:1055");

  script_name(english:"RHEL 5 : kernel (RHSA-2009:1055)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix one security issue and a bug are now
available for Red Hat Enterprise Linux 5.2 Extended Update Support.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issue :

* a buffer overflow was found in the Linux kernel Partial Reliable
Stream Control Transmission Protocol (PR-SCTP) implementation. This
could, potentially, lead to a remote denial of service or arbitrary
code execution if a Forward-TSN chunk is received with a large stream
ID. Note: An established connection between SCTP endpoints is
necessary to exploit this vulnerability. Refer to the Knowledgebase
article in the References section for further information.
(CVE-2009-0065, Important)

This update also fixes the following bug :

* a problem in the way the i5000_edac module reported errors may have
caused the console on some systems to be flooded with errors, similar
to the following :

EDAC i5000 MC0: NON-FATAL ERROR Found!!! 1st NON-FATAL Err Reg= [hex
value] EDAC i5000: NON-Retry Errors, bits= [hex value]

After installing this update, the console will not be flooded with
these errors. (BZ#494734)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0065.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kbase.redhat.com/faq/docs/DOC-16788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1055.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i686", reference:"kernel-2.6.18-92.1.26.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"s390x", reference:"kernel-2.6.18-92.1.26.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"x86_64", reference:"kernel-2.6.18-92.1.26.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i686", reference:"kernel-PAE-2.6.18-92.1.26.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i686", reference:"kernel-PAE-devel-2.6.18-92.1.26.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i686", reference:"kernel-debug-2.6.18-92.1.26.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"s390x", reference:"kernel-debug-2.6.18-92.1.26.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"x86_64", reference:"kernel-debug-2.6.18-92.1.26.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i686", reference:"kernel-debug-devel-2.6.18-92.1.26.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"s390x", reference:"kernel-debug-devel-2.6.18-92.1.26.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"x86_64", reference:"kernel-debug-devel-2.6.18-92.1.26.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i686", reference:"kernel-devel-2.6.18-92.1.26.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"s390x", reference:"kernel-devel-2.6.18-92.1.26.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"x86_64", reference:"kernel-devel-2.6.18-92.1.26.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", reference:"kernel-doc-2.6.18-92.1.26.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i386", reference:"kernel-headers-2.6.18-92.1.26.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"s390x", reference:"kernel-headers-2.6.18-92.1.26.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"x86_64", reference:"kernel-headers-2.6.18-92.1.26.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"s390x", reference:"kernel-kdump-2.6.18-92.1.26.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"s390x", reference:"kernel-kdump-devel-2.6.18-92.1.26.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i686", reference:"kernel-xen-2.6.18-92.1.26.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"x86_64", reference:"kernel-xen-2.6.18-92.1.26.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"i686", reference:"kernel-xen-devel-2.6.18-92.1.26.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"2", cpu:"x86_64", reference:"kernel-xen-devel-2.6.18-92.1.26.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
