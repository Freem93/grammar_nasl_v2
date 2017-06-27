#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2015-0006.
#

include("compat.inc");

if (description)
{
  script_id(81012);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2014-8137", "CVE-2014-8138", "CVE-2014-8157", "CVE-2014-8158", "CVE-2014-9029");
  script_bugtraq_id(71476, 71742, 71746, 72293, 72296);
  script_osvdb_id(77595, 115355, 115481, 115482, 116027, 116028, 117408, 117409);

  script_name(english:"OracleVM 3.3 : jasper (OVMSA-2015-0006)");
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

  - CVE-2014-8157 - dec->numtiles off-by-one check in
    jpc_dec_process_sot (#1183671)

  - CVE-2014-8158 - unrestricted stack memory use in
    jpc_qmfb.c (#1183679)

  - CVE-2014-8137 - double-free in in jas_iccattrval_destroy
    (#1173566)

  - CVE-2014-8138 - heap overflow in jp2_decode (#1173566)

  - CVE-2014-9029 - incorrect component number check in COC,
    RGN and QCC marker segment decoders (#1171208)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2015-January/000258.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29ad807c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected jasper-libs package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:jasper-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/27");
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
if (rpm_check(release:"OVS3.3", reference:"jasper-libs-1.900.1-16.el6_6.3")) flag++;

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
