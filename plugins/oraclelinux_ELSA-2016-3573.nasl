#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2016-3573.
#

include("compat.inc");

if (description)
{
  script_id(91592);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/19 14:25:11 $");

  script_cve_id("CVE-2016-4565");

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2016-3573)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

kernel-uek
[3.8.13-118.7.1.el7uek]
- megaraid_sas : Update threshold based reply post host index register 
(<A HREF='https://oss.oracle.com/mailman/listinfo/el-errata'>Sumit.Saxena at avagotech.com</A>)  [Orabug: 23562756]
- xen/events: Don't move disabled irqs (Ross Lagerwall)  [Orabug: 23055234]
- xen/events: Mask a moving irq (Boris Ostrovsky)  [Orabug: 23055234]
- xen/pciback: Save the number of MSI-X entries to be copied later. 
(Dongli Zhang)  [Orabug: 23202410]
- xen/pciback: Save xen_pci_op commands before processing it (Dongli 
Zhang)  [Orabug: 23202410]
- xen-blkback: read from indirect descriptors only once (Dongli Zhang) 
[Orabug: 23202410]
- xen-blkback: only read request operation from shared ring once (Dongli 
Zhang)  [Orabug: 23202410]
- xen-netback: use RING_COPY_REQUEST() throughout (Dongli Zhang) 
[Orabug: 23202410]
- xen-netback: don't use last request to determine minimum Tx credit 
(Dongli Zhang)  [Orabug: 23202410]
- xen: Add RING_COPY_REQUEST() (Dongli Zhang)  [Orabug: 23202410]
- IB/security: Restrict use of the write() interface (Jason Gunthorpe) 
[Orabug: 23283925]  {CVE-2016-4565}"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-June/006110.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-June/006111.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-3.8.13-118.7.1.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-3.8.13-118.7.1.el7uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"dtrace-modules-3.8.13-118.7.1.el6uek-0.4.5-3.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-3.8.13") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-3.8.13-118.7.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-3.8.13") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-debug-3.8.13-118.7.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-3.8.13") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-debug-devel-3.8.13-118.7.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-3.8.13") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-devel-3.8.13-118.7.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-3.8.13") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-doc-3.8.13-118.7.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-3.8.13") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-firmware-3.8.13-118.7.1.el6uek")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"dtrace-modules-3.8.13-118.7.1.el7uek-0.4.5-3.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-3.8.13-118.7.1.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-3.8.13-118.7.1.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-devel-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-devel-3.8.13-118.7.1.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-devel-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-devel-3.8.13-118.7.1.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-doc-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-doc-3.8.13-118.7.1.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-firmware-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-firmware-3.8.13-118.7.1.el7uek")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
