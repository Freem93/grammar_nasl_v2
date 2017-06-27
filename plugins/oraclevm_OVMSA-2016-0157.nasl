#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0157.
#

include("compat.inc");

if (description)
{
  script_id(94909);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/02/14 17:23:20 $");

  script_cve_id("CVE-2016-7545");
  script_osvdb_id(144760);

  script_name(english:"OracleVM 3.3 / 3.4 : policycoreutils (OVMSA-2016-0157)");
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

  - Lazy unmount private, shared entry(Joe Jin)[orabug
    12560705]

  - sandbox: create a new session for sandboxed processes
    Resolves: (CVE-2016-7545)

  - Update translations Resolves: rhbz#819794

  - Fix sepolgen test cases Resolves: rhbz#1306550

  - sandbox: Improve comments in sysconfig file Resolves:
    rhbz#1159336

  - secon, newrole: fix inconsistence between --help and man
    page Resolves: rhbz#1278811, rhbz#1278913

  - restorecond: treat root as a regular user Resolves:
    rhbz#1281877

  - semanage: don't skip reserver_port_t Resolves:
    rhbz#1225806

  - semanage: check if a store exists Resolves: rhbz#1208801

  - fixfiles: check the SELinux status Resolves:
    rhbz#1240788

  - semanage: Use OrderedDict for list of fcontexts
    Resolves: rhbz#1206767"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-November/000581.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d3c3c250"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-November/000580.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ea3d222"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected policycoreutils package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UC");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:U");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:policycoreutils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/16");
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
if (! ereg(pattern:"^OVS" + "(3\.3|3\.4)" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3 / 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"policycoreutils-2.0.83-30.1.0.1.el6_8")) flag++;

if (rpm_check(release:"OVS3.4", reference:"policycoreutils-2.0.83-30.1.0.1.el6_8")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "policycoreutils");
}
