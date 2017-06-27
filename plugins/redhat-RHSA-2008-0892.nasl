#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0892. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34329);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2017/01/03 17:16:34 $");

  script_cve_id("CVE-2008-1945", "CVE-2008-1952");
  script_osvdb_id(45443, 46542, 48798);
  script_xref(name:"RHSA", value:"2008:0892");

  script_name(english:"RHEL 5 : xen (RHSA-2008:0892)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xen packages that resolve a couple of security issues and fix
a bug are now available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The xen packages contain tools for managing the virtual machine
monitor in Red Hat Virtualization.

It was discovered that the hypervisor's para-virtualized framebuffer
(PVFB) backend failed to validate the frontend's framebuffer
description properly. This could allow a privileged user in the
unprivileged domain (DomU) to cause a denial of service, or, possibly,
elevate privileges to the privileged domain (Dom0). (CVE-2008-1952)

A flaw was found in the QEMU block format auto-detection, when running
fully-virtualized guests and using Qemu images written on removable
media (USB storage, 3.5' disks). Privileged users of such
fully-virtualized guests (DomU), with a raw-formatted disk image, were
able to write a header to that disk image describing another format.
This could allow such guests to read arbitrary files in their
hypervisor's host (Dom0). (CVE-2008-1945)

Additionally, the following bug is addressed in this update :

* The qcow-create command terminated when invoked due to glibc bounds
checking on the realpath() function.

Users of xen are advised to upgrade to these updated packages, which
resolve these security issues and fix this bug."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1945.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1952.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0892.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen, xen-devel and / or xen-libs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_cwe_id(119, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0892";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"xen-3.0.3-64.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"xen-3.0.3-64.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"xen-devel-3.0.3-64.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"xen-devel-3.0.3-64.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"xen-libs-3.0.3-64.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"xen-libs-3.0.3-64.el5_2.3")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-devel / xen-libs");
  }
}
