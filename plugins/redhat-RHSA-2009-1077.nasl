#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1077. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63880);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/10 18:05:23 $");

  script_cve_id("CVE-2009-1336", "CVE-2009-1337");
  script_xref(name:"RHSA", value:"2009:1077");

  script_name(english:"RHEL 4 : kernel (RHSA-2009:1077)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix two security issues and two bugs are
now available for Red Hat Enterprise Linux 4.7 Extended Update
Support.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update includes backported fixes for two approved security
issues. These issues only affected users of Red Hat Enterprise Linux
4.7 Extended Update Support, as they have already been addressed for
users of Red Hat Enterprise Linux 4 in the 4.8 update, RHSA-2009:1024.

* the exit_notify() function in the Linux kernel did not properly
reset the exit signal if a process executed a set user ID (setuid)
application before exiting. This could allow a local, unprivileged
user to elevate their privileges. (CVE-2009-1337, Important)

* the Linux kernel implementation of the Network File System (NFS)
version 4 did not properly initialize the file name limit in the
nfs_server data structure. This flaw could possibly lead to a denial
of service on a client mounting an NFSv4 share. (CVE-2009-1336,
Moderate)

This update fixes the following bugs :

* on IBM System z systems, if the cio driver was used for DASD
devices, and the last path to a DASD device was varied off, it was
still possible to attempt read and write operations to that device,
resulting in errors. In this update, path verification is used in this
situation, which resolves this issue. Also, a bug may have caused
errors when subchannels were unregistered. (BZ#437486)

* a bug prevented the Broadcom NetXtreme II 57710 network device from
working correctly on some Dell PowerEdge R805 systems. This device was
correctly shown in 'lspci' output, but 'ifup' failed and an IP address
was not assigned. In this update, the device works correctly on Dell
PowerEdge R805 systems. (BZ#491752)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. For this update to take
effect, the system must be rebooted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-1336.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-1337.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1077.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20, 264);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/02");
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
if (rpm_check(release:"RHEL4", sp:"7", reference:"kernel-2.6.9-78.0.24.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", reference:"kernel-devel-2.6.9-78.0.24.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", reference:"kernel-doc-2.6.9-78.0.24.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"i686", reference:"kernel-hugemem-2.6.9-78.0.24.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"i686", reference:"kernel-hugemem-devel-2.6.9-78.0.24.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-78.0.24.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-78.0.24.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"i686", reference:"kernel-smp-2.6.9-78.0.24.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"x86_64", reference:"kernel-smp-2.6.9-78.0.24.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"i686", reference:"kernel-smp-devel-2.6.9-78.0.24.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-78.0.24.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"i686", reference:"kernel-xenU-2.6.9-78.0.24.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"x86_64", reference:"kernel-xenU-2.6.9-78.0.24.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"i686", reference:"kernel-xenU-devel-2.6.9-78.0.24.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"x86_64", reference:"kernel-xenU-devel-2.6.9-78.0.24.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
