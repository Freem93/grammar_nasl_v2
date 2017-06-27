#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0436 and 
# Oracle Linux Security Advisory ELSA-2007-0436 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67516);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:16:27 $");

  script_cve_id("CVE-2006-5823", "CVE-2006-6054", "CVE-2007-1592");
  script_bugtraq_id(23104);
  script_osvdb_id(30215, 30295, 34365);
  script_xref(name:"RHSA", value:"2007:0436");

  script_name(english:"Oracle Linux 3 : kernel (ELSA-2007-0436)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0436 :

Updated kernel packages are now available as part of ongoing support
and maintenance of Red Hat Enterprise Linux version 3. This is the
ninth regular update.

This security advisory has been rated as having important security
impact by the Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

This is the ninth regular kernel update to Red Hat Enterprise Linux 3.

There were no new features introduced by this update. The only changes
that have been included address critical customer needs or security
issues (elaborated below).

Key areas affected by fixes in this update include the networking
subsystem, dcache handling, the ext2 and ext3 file systems, the USB
subsystem, ACPI handling, and the audit subsystem. There were also
several isolated fixes in the tg3, e1000, megaraid_sas, and aacraid
device drivers.

The following security bugs were fixed in this update :

* a flaw in the cramfs file system that allowed invalid compressed
data to cause memory corruption (CVE-2006-5823, low)

* a flaw in the ext2 file system that allowed an invalid inode size to
cause a denial of service (system hang) (CVE-2006-6054, low)

* a flaw in IPV6 flow label handling that allowed a local user to
cause a denial of service (crash) (CVE-2007-1592, important)

Note: The kernel-unsupported package contains various drivers and
modules that are unsupported and therefore might contain security
problems that have not been addressed.

All Red Hat Enterprise Linux 3 users are advised to upgrade their
kernels to the packages associated with their machine architectures
and configurations as listed in this erratum."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-June/000177.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/07");
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
if (rpm_exists(release:"EL3", rpm:"kernel-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-2.4.21-50.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-2.4.21") && rpm_check(release:"EL3", cpu:"x86_64", reference:"kernel-2.4.21-50.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-BOOT-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-BOOT-2.4.21-50.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-doc-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-doc-2.4.21-50.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-doc-2.4.21") && rpm_check(release:"EL3", cpu:"x86_64", reference:"kernel-doc-2.4.21-50.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-hugemem-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-hugemem-2.4.21-50.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-hugemem-unsupported-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-hugemem-unsupported-2.4.21-50.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-smp-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-smp-2.4.21-50.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-smp-2.4.21") && rpm_check(release:"EL3", cpu:"x86_64", reference:"kernel-smp-2.4.21-50.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-smp-unsupported-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-smp-unsupported-2.4.21-50.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-smp-unsupported-2.4.21") && rpm_check(release:"EL3", cpu:"x86_64", reference:"kernel-smp-unsupported-2.4.21-50.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-source-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-source-2.4.21-50.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-source-2.4.21") && rpm_check(release:"EL3", cpu:"x86_64", reference:"kernel-source-2.4.21-50.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-unsupported-2.4.21") && rpm_check(release:"EL3", cpu:"i386", reference:"kernel-unsupported-2.4.21-50.EL")) flag++;
if (rpm_exists(release:"EL3", rpm:"kernel-unsupported-2.4.21") && rpm_check(release:"EL3", cpu:"x86_64", reference:"kernel-unsupported-2.4.21-50.EL")) flag++;


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
