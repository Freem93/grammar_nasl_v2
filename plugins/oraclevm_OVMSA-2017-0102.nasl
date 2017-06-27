#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0102.
#

include("compat.inc");

if (description)
{
  script_id(100116);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/11 13:20:58 $");

  script_cve_id("CVE-2014-8137", "CVE-2014-8138", "CVE-2014-8157", "CVE-2014-8158", "CVE-2014-9029", "CVE-2015-5203", "CVE-2015-5221", "CVE-2016-10248", "CVE-2016-10249", "CVE-2016-10251", "CVE-2016-1577", "CVE-2016-1867", "CVE-2016-2089", "CVE-2016-2116", "CVE-2016-8654", "CVE-2016-8690", "CVE-2016-8691", "CVE-2016-8692", "CVE-2016-8693", "CVE-2016-8883", "CVE-2016-8884", "CVE-2016-8885", "CVE-2016-9262", "CVE-2016-9387", "CVE-2016-9388", "CVE-2016-9389", "CVE-2016-9390", "CVE-2016-9391", "CVE-2016-9392", "CVE-2016-9393", "CVE-2016-9394", "CVE-2016-9560", "CVE-2016-9583", "CVE-2016-9591", "CVE-2016-9600");
  script_bugtraq_id(71476, 71742, 71746, 72293, 72296);
  script_osvdb_id(77595, 115355, 115481, 115482, 116027, 116028, 117408, 117409, 126344, 126557, 132886, 133755, 135285, 135286, 143483, 143484, 143485, 145760, 146140, 146183, 146707, 147104, 147462, 147499, 147505, 147506, 147507, 147508, 147509, 147666, 147946, 148760, 148845, 151469);

  script_name(english:"OracleVM 3.3 / 3.4 : jasper (OVMSA-2017-0102)");
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

  - Bump release

  - Multiple security fixes (fixed by thoger): CVE-2015-5203
    CVE-2015-5221 CVE-2016-1577 CVE-2016-1867
    (CVE-2016-2089) CVE-2016-2116 CVE-2016-8654
    CVE-2016-8690 CVE-2016-8691 (CVE-2016-8692)
    CVE-2016-8693 CVE-2016-8883 CVE-2016-8884 CVE-2016-8885
    (CVE-2016-9262) CVE-2016-9387 CVE-2016-9388
    CVE-2016-9389 CVE-2016-9390 (CVE-2016-9391)
    CVE-2016-9392 CVE-2016-9393 CVE-2016-9394 CVE-2016-9560
    (CVE-2016-9583) CVE-2016-9591 CVE-2016-9600
    CVE-2016-10248 CVE-2016-10249 (CVE-2016-10251)

  - Fix implicit declaration warning caused by security
    fixes above

  - CVE-2014-8157 - dec->numtiles off-by-one check in
    jpc_dec_process_sot (#1183672)

  - CVE-2014-8158 - unrestricted stack memory use in
    jpc_qmfb.c (#1183680)

  - CVE-2014-8137 - double-free in in jas_iccattrval_destroy
    (#1173567)

  - CVE-2014-8138 - heap overflow in jp2_decode (#1173567)

  - CVE-2014-9029 - incorrect component number check in COC,
    RGN and QCC marker segment decoders (#1171209)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2017-May/000695.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2017-May/000696.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected jasper-libs package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:jasper-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/11");
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
if (rpm_check(release:"OVS3.3", reference:"jasper-libs-1.900.1-21.el6_9")) flag++;

if (rpm_check(release:"OVS3.4", reference:"jasper-libs-1.900.1-21.el6_9")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jasper-libs");
}
