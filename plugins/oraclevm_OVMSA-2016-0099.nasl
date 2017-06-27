#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0099.
#

include("compat.inc");

if (description)
{
  script_id(93038);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2017/02/14 17:23:20 $");

  script_cve_id("CVE-2016-0772", "CVE-2016-1000110", "CVE-2016-5699");
  script_osvdb_id(115884, 140038, 141671);

  script_name(english:"OracleVM 3.3 / 3.4 : python (OVMSA-2016-0099) (httpoxy)");
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

  - Add Oracle Linux distribution in platform.py [orabug
    21288328] (Keshav Sharma)

  - Fix for CVE-2016-1000110 HTTPoxy attack Resolves:
    rhbz#1359161

  - Fix for CVE-2016-0772 python: smtplib StartTLS stripping
    attack (rhbz#1303647) Raise an error when STARTTLS fails
    (upstream patch)

  - Fix for CVE-2016-5699 python: http protocol steam
    injection attack (rhbz#1303699) Disabled HTTP header
    injections in httplib (upstream patch) Resolves:
    rhbz#1346354"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-August/000516.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ee4ea01f"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-August/000514.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5114db7e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python / python-libs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:python-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/18");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/19");
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
if (rpm_check(release:"OVS3.3", reference:"python-2.6.6-66.0.1.el6_8")) flag++;
if (rpm_check(release:"OVS3.3", reference:"python-libs-2.6.6-66.0.1.el6_8")) flag++;

if (rpm_check(release:"OVS3.4", reference:"python-2.6.6-66.0.1.el6_8")) flag++;
if (rpm_check(release:"OVS3.4", reference:"python-libs-2.6.6-66.0.1.el6_8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python / python-libs");
}
