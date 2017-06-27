#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0037.
#

include("compat.inc");

if (description)
{
  script_id(90019);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2010-5313", "CVE-2012-3520", "CVE-2013-7421", "CVE-2014-3215", "CVE-2014-7842", "CVE-2014-8133", "CVE-2014-8159", "CVE-2014-9419", "CVE-2014-9420", "CVE-2014-9584", "CVE-2014-9585", "CVE-2014-9644", "CVE-2014-9683", "CVE-2014-9715", "CVE-2015-0239", "CVE-2015-1421", "CVE-2015-1593", "CVE-2015-2150", "CVE-2015-2830", "CVE-2015-2922", "CVE-2015-3331", "CVE-2015-3339", "CVE-2015-3636", "CVE-2015-5156", "CVE-2015-5307", "CVE-2015-5364", "CVE-2015-5366", "CVE-2015-5697", "CVE-2015-7613", "CVE-2015-7872", "CVE-2015-8104");
  script_bugtraq_id(55152, 67341, 71078, 71363, 71684, 71717, 71794, 71883, 71990, 72320, 72322, 72356, 72607, 72643, 72842, 73014, 73060, 73699, 73953, 74235, 74243, 74315, 74450, 75510);
  script_osvdb_id(114689, 115920, 116075, 116259, 116767, 116910, 117716, 117749, 117762, 118498, 118625, 119409, 119630, 120282, 120284, 120540, 121011, 121170, 121578, 123996, 125431, 125846, 128379, 129330, 130089, 130090);

  script_name(english:"OracleVM 3.2 : kernel-uek (OVMSA-2016-0037)");
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
OVMSA-2016-0037 for details."
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-March/000442.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8111de50"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/18");
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
if (! ereg(pattern:"^OVS" + "3\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.2", reference:"kernel-uek-2.6.39-400.277.1.el5uek")) flag++;
if (rpm_check(release:"OVS3.2", reference:"kernel-uek-firmware-2.6.39-400.277.1.el5uek")) flag++;

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
