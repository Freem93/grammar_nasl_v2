#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0088.
#

include("compat.inc");

if (description)
{
  script_id(92600);
  script_version("$Revision: 2.11 $");
  script_cvs_date("$Date: 2017/02/17 16:18:34 $");

  script_cve_id("CVE-2016-2270", "CVE-2016-3158", "CVE-2016-3159", "CVE-2016-3960", "CVE-2016-4480", "CVE-2016-4962", "CVE-2016-6258");
  script_osvdb_id(134693, 136473, 137353, 138720, 139322, 142140);
  script_xref(name:"IAVB", value:"2016-B-0118");

  script_name(english:"OracleVM 3.4 : xen (OVMSA-2016-0088) (Bunker Buster)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - BUILDINFO:
    commit=aff08b43b1a504aa14a0fce65302ccf515b69fdf

  - Remove unsafe bits from the mod_l?_entry fastpath
    (Andrew Cooper) (CVE-2016-6258)

  - x86/mm: fully honor PS bits in guest page table walks
    (Jan Beulich) (CVE-2016-4480) (CVE-2016-4480)

  - libxl: Document ~/serial/ correctly (Ian Jackson)
    (CVE-2016-4962)

  - libxl: Cleanup: Have libxl__alloc_vdev use /libxl (Ian
    Jackson) (CVE-2016-4962)

  - libxl: Do not trust frontend for nic in getinfo (Ian
    Jackson) (CVE-2016-4962)

  - libxl: Do not trust frontend for nic in
    libxl_devid_to_device_nic (Ian Jackson) (CVE-2016-4962)

  - libxl: Do not trust frontend for vtpm in getinfo (Ian
    Jackson) (CVE-2016-4962)

  - libxl: Do not trust frontend for vtpm list (Ian Jackson)
    (CVE-2016-4962)

  - libxl: Do not trust frontend for disk in getinfo (Ian
    Jackson) (CVE-2016-4962)

  - libxl: Do not trust frontend for disk eject event (Ian
    Jackson) (CVE-2016-4962)

  - libxl: Do not trust frontend in libxl__device_nextid
    (Ian Jackson) (CVE-2016-4962)

  - libxl: Do not trust frontend in libxl__devices_destroy
    (Ian Jackson) (CVE-2016-4962)

  - libxl: Provide libxl__backendpath_parse_domid (Ian
    Jackson) (CVE-2016-4962)

  - libxl: Record backend/frontend paths in /libxl/$DOMID
    (Ian Jackson) (CVE-2016-4962)

  - x86: limit GFNs to 32 bits for shadowed superpages. (Tim
    Deegan) (CVE-2016-3960)

  - x86: fix information leak on AMD CPUs (Jan Beulich)
    (CVE-2016-3158) (CVE-2016-3159) (CVE-2016-3158)
    (CVE-2016-3159) (CVE-2016-3158) (CVE-2016-3159)

  - x86: enforce consistent cachability of MMIO mappings
    (Jan Beulich) (CVE-2016-2270) (CVE-2016-2270)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2016-July/000503.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/27");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/28");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.4", reference:"xen-4.4.4-75.0.1.el6")) flag++;
if (rpm_check(release:"OVS3.4", reference:"xen-tools-4.4.4-75.0.1.el6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-tools");
}
