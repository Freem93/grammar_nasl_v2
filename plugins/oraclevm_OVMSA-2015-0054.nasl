#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2015-0054.
#

include("compat.inc");

if (description)
{
  script_id(82692);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2014-5352", "CVE-2014-5353", "CVE-2014-5355", "CVE-2014-9421", "CVE-2014-9422");
  script_bugtraq_id(71679, 72494, 72495, 72496, 74042);
  script_osvdb_id(115960, 117920, 117921, 117922, 118567, 118568, 118569, 118570);

  script_name(english:"OracleVM 3.3 : krb5 (OVMSA-2015-0054)");
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

  - fix for CVE-2014-5355 (#1193939) 'krb5: unauthenticated
    denial of service in recvauth_common and others'

  - fix for CVE-2014-5353 (#1174543) 'Fix LDAP misused
    policy name crash'

  - Changelog fixes to make errata subsystem happy.

  - fix for CVE-2014-5352 (#1179856)
    'gss_process_context_token incorrectly frees context
    (MITKRB5-SA-2015-001)'

  - fix for CVE-2014-9421 (#1179857) 'kadmind doubly frees
    partial deserialization results (MITKRB5-SA-2015-001)'

  - fix for CVE-2014-9422 (#1179861) 'kadmind incorrectly
    validates server principal name (MITKRB5-SA-2015-001)'"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2015-April/000295.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61688492"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected krb5-libs package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/09");
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
if (rpm_check(release:"OVS3.3", reference:"krb5-libs-1.10.3-37.el6_6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-libs");
}
