#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2015-0040.
#

include("compat.inc");

if (description)
{
  script_id(82691);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/04/10 13:19:30 $");

  script_cve_id("CVE-2013-7421", "CVE-2014-3182", "CVE-2014-3186", "CVE-2014-3601", "CVE-2014-3610", "CVE-2014-3688", "CVE-2014-4027", "CVE-2014-4652", "CVE-2014-4656", "CVE-2014-5471", "CVE-2014-5472", "CVE-2014-6410", "CVE-2014-7826", "CVE-2014-7970", "CVE-2014-7975", "CVE-2014-8133", "CVE-2014-8134", "CVE-2014-8159", "CVE-2014-8160", "CVE-2014-8173", "CVE-2014-8884", "CVE-2014-9090", "CVE-2014-9322", "CVE-2014-9644", "CVE-2015-1421", "CVE-2015-2150");
  script_bugtraq_id(67985, 68159, 68163, 68170, 69396, 69428, 69489, 69763, 69770, 69799, 70314, 70319, 70742, 70768, 70971, 71097, 71250, 71650, 71684, 71685, 72061, 72320, 72322, 72356, 73014, 73060, 73133);
  script_osvdb_id(108001, 108386, 108389, 108390, 110240, 110564, 110565, 111406, 111430, 113014, 113726, 113823, 114370, 114957, 115163, 115870, 115919, 115920, 117131, 117716, 117749, 119233, 119409, 119630);

  script_name(english:"OracleVM 3.3 : kernel-uek (OVMSA-2015-0040)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates : please see Oracle VM Security Advisory
OVMSA-2015-0040 for details."
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2015-April/000292.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2787d9ec"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"kernel-uek-3.8.13-68.1.2.el6uek")) flag++;
if (rpm_check(release:"OVS3.3", reference:"kernel-uek-firmware-3.8.13-68.1.2.el6uek")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
