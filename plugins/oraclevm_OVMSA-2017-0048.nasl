#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0048.
#

include("compat.inc");

if (description)
{
  script_id(97908);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/23 13:29:51 $");

  script_cve_id("CVE-2013-1447", "CVE-2013-6045", "CVE-2013-6052", "CVE-2013-6054", "CVE-2016-5139", "CVE-2016-5158", "CVE-2016-5159", "CVE-2016-7163", "CVE-2016-9675");
  script_bugtraq_id(64109, 64113, 64118, 64142);
  script_osvdb_id(100636, 100637, 100638, 100641, 100646, 142530, 142663, 142664, 143027, 143652);

  script_name(english:"OracleVM 3.3 / 3.4 : openjpeg (OVMSA-2017-0048)");
  script_summary(english:"Checks the RPM output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - Revert previous changes in patch for (CVE-2016-5159)

  - Fix double free in patch for (CVE-2016-5139)

  - Fix memory leaks and invalid read in cio_bytein Related:
    #1419775

  - Add two more allocation checks to patch for
    (CVE-2016-5159) Related: #1419775

  - Add patches for CVE-2016-5139, CVE-2016-5158,
    (CVE-2016-5159) Related: #1419775

  - Fix patch name: CVE-2016-9675 => (CVE-2016-7163)
    Related: #1419775

  - Add patch for (CVE-2016-9675)

  - Fix Coverity issues Resolves: #1419775"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-March/000658.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d0889d16"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-March/000657.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8fc7ae70"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openjpeg-libs package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:openjpeg-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^OVS" + "(3\.3|3\.4)" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3 / 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"openjpeg-libs-1.3-16.el6_8")) flag++;

if (rpm_check(release:"OVS3.4", reference:"openjpeg-libs-1.3-16.el6_8")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openjpeg-libs");
}
