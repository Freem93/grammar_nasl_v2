#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2002:128. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12306);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/28 17:44:42 $");

  script_cve_id("CVE-2002-1571");
  script_xref(name:"RHSA", value:"2002:128");

  script_name(english:"RHEL 2.1 : kernel (RHSA-2002:128)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update is available for Red Hat Linux Advanced Server 2.1.

It includes a fix for an information security bug, various kernel bug
fixes, and updated device drivers.

[2002-07-29] This release is a rebuild for adding exported symbols for
Veritas.

This kernel fixes an information security bug. When running enterprise
kernels previous to version 2.4.9-e.8, information in the Intel SSE
XMM registers could 'leak' between processes under certain
circumstances.

This update also includes fixes for the following bugs :

  - Creation of an Oracle SGA greater than 8 GB on 16 GB or
    greater machine when using bigpages and shmfs - Sendmail
    running out of flocks - Unreliable rebooting with the
    'reboot=bios' boot option - Potential memory corruption
    on systems with more than 4 GB - An AIO write deadlock -
    IOAPIC warnings on one platform - Potentially
    miscompiled code in xor.h (though kernel engineering
    research does not indicate that our compiler miscompiles
    this code)

This kernel also has extra exported symbols removed.

This new kernel also includes several updated device drivers. The
aic7xxx_mod driver has been updated to a new version, fixing several
bugs, the tg3 driver has also been updated to a new version to fix
various bugs, and the qla2300 driver has some small bug fixes and has
been updated to work with the QLogic 2340 HBA and PowerVault 660F
arrays. Additions to the SCSI LUNs 'white list' have also been made to
support more fibre channel arrays.

[2002-07-29] This new kernel is a rebuild for adding exported symbols
for Veritas."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-1571.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2002-128.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-BOOT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-enterprise");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-summit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^2\.1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2002:128";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
  if (rpm_check(release:"RHEL2.1", cpu:"i686", reference:"kernel-2.4.9-e.8")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kernel-BOOT-2.4.9-e.8")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i686", reference:"kernel-debug-2.4.9-e.8")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kernel-doc-2.4.9-e.8")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i686", reference:"kernel-enterprise-2.4.9-e.8")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kernel-headers-2.4.9-e.8")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i686", reference:"kernel-smp-2.4.9-e.8")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kernel-source-2.4.9-e.8")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i686", reference:"kernel-summit-2.4.9-e.8")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-BOOT / kernel-debug / kernel-doc / etc");
  }
}
