#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2015-0002.
#

include("compat.inc");

if (description)
{
  script_id(80395);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2009-0021", "CVE-2009-0159", "CVE-2009-1252", "CVE-2009-3563", "CVE-2014-9293", "CVE-2014-9294", "CVE-2014-9295");
  script_bugtraq_id(33150, 34481, 35017, 37255, 71757, 71761, 71762);
  script_osvdb_id(53593, 54576, 60847, 116066, 116067, 116068, 116069, 116074);

  script_name(english:"OracleVM 2.2 : ntp (OVMSA-2015-0002)");
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

  - don't generate weak control key for resolver
    (CVE-2014-9293)

  - don't generate weak MD5 keys in ntp-keygen
    (CVE-2014-9294)

  - fix buffer overflows via specially-crafted packets
    (CVE-2014-9295)

  - increase memlock limit again (#1035198)

  - allow selection of cipher for private key files
    (#741573)

  - revert init script priority (#470945, #689636)

  - drop tentative patch (#489835)

  - move restorecon call to %posttrans

  - call restorecon on ntpd and ntpdate on start (#470945)

  - don't crash with more than 512 local addresses (#661934)

  - add -I option (#528799)

  - fix -L option to not require argument (#460434)

  - move ntpd and ntpdate to /sbin and start earlier on boot
    (#470945, #689636)

  - increase memlock limit (#575874)

  - ignore tentative addresses (#489835)

  - print synchronization distance instead of dispersion in
    ntpstat (#679034)

  - fix typos in ntpq and ntp-keygen man pages (#664524,
    #664525)

  - clarify ntpd -q description (#591838)

  - don't verify ntp.conf (#481151)

  - replace Prereq tag

  - fix DoS with mode 7 packets (#532640, CVE-2009-3563)

  - compile with -fno-strict-aliasing

  - fix buffer overflow when parsing Autokey association
    message (#500784, CVE-2009-1252)

  - fix buffer overflow in ntpq (#500784, CVE-2009-0159)

  - fix check for malformed signatures (#479699,
    CVE-2009-0021)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2015-January/000253.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb11e689"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ntp package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:ntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/07");
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
if (! ereg(pattern:"^OVS" + "2\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 2.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);

flag = 0;
if (rpm_check(release:"OVS2.2", reference:"ntp-4.2.2p1-18.el5_11")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp");
}
