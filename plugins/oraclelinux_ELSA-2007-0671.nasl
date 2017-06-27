#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0671 and 
# Oracle Linux Security Advisory ELSA-2007-0671 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67540);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:16:27 $");

  script_cve_id("CVE-2007-1217", "CVE-2007-1353");
  script_osvdb_id(34739, 34742);
  script_xref(name:"RHSA", value:"2007:0671");

  script_name(english:"Oracle Linux 3 : kernel (ELSA-2007-0671)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0671 :

Updated kernel packages that fix several security issues and bugs in
the Red Hat Enterprise Linux 3 kernel are now available.

This security advisory has been rated as having moderate security
impact by the Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

These new kernel packages contain fixes for the security issues
described below :

* a flaw in the ISDN CAPI subsystem that allowed a remote user to
cause a denial of service or potential privilege escalation.
(CVE-2007-1217, Moderate)

* a flaw in the Bluetooth subsystem that allowed a local user to
trigger an information leak. (CVE-2007-1353, Low)

In addition to the security issues described above, fixes for the
following have been included :

* a race condition in the e1000 network driver that could cause ESB2
systems to be started without the RX unit being turned on.

* a related e1000 bug on ESB2 systems that could cause rlogin to fail.

Red Hat would like to thank Ilja van Sprundel for reporting an issue
fixed in this erratum.

Note: The kernel-unsupported package contains various drivers and
modules that are unsupported and therefore might contain security
problems that have not been addressed.

All Red Hat Enterprise Linux 3 users are advised to upgrade their
kernels to the packages associated with their machine architecture and
configurations as listed in this erratum."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-August/000302.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-BOOT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-hugemem-unsupported");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-smp-unsupported");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-unsupported");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_exists(release:"EL3", rpm:"kernel-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-2.4.21-51.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-2.4.21") && rpm_check(release:"EL3", cpu:"x86_64", reference:"kernel-2.4.21-51.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-BOOT-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-BOOT-2.4.21-51.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-doc-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-doc-2.4.21-51.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-doc-2.4.21") && rpm_check(release:"EL3", cpu:"x86_64", reference:"kernel-doc-2.4.21-51.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-hugemem-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-hugemem-2.4.21-51.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-hugemem-unsupported-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-hugemem-unsupported-2.4.21-51.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-smp-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-smp-2.4.21-51.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-smp-2.4.21") && rpm_check(release:"EL3", cpu:"x86_64", reference:"kernel-smp-2.4.21-51.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-smp-unsupported-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-smp-unsupported-2.4.21-51.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-smp-unsupported-2.4.21") && rpm_check(release:"EL3", cpu:"x86_64", reference:"kernel-smp-unsupported-2.4.21-51.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-source-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-source-2.4.21-51.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-source-2.4.21") && rpm_check(release:"EL3", cpu:"x86_64", reference:"kernel-source-2.4.21-51.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-unsupported-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-unsupported-2.4.21-51.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-unsupported-2.4.21") && rpm_check(release:"EL3", cpu:"x86_64", reference:"kernel-unsupported-2.4.21-51.EL")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
