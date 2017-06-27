#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:0892 and 
# Oracle Linux Security Advisory ELSA-2008-0892 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67749);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/07 20:57:50 $");

  script_cve_id("CVE-2008-1945", "CVE-2008-1952");
  script_osvdb_id(45443, 46542, 48798);
  script_xref(name:"RHSA", value:"2008:0892");

  script_name(english:"Oracle Linux 5 : xen (ELSA-2008-0892)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2008:0892 :

Updated xen packages that resolve a couple of security issues and fix
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
    value:"https://oss.oracle.com/pipermail/el-errata/2008-October/000745.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_cwe_id(119, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"xen-3.0.3-64.el5_2.3")) flag++;
if (rpm_check(release:"EL5", reference:"xen-devel-3.0.3-64.el5_2.3")) flag++;
if (rpm_check(release:"EL5", reference:"xen-libs-3.0.3-64.el5_2.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-devel / xen-libs");
}
