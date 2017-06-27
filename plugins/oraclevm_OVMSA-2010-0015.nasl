#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2010-0015.
#

include("compat.inc");

if (description)
{
  script_id(68878);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/02/17 16:18:34 $");

  script_cve_id("CVE-2010-3582", "CVE-2010-3583", "CVE-2010-3584", "CVE-2010-3585");
  script_bugtraq_id(44031, 44043, 44044, 44047);
  script_xref(name:"IAVA", value:"2010-A-0151");

  script_name(english:"OracleVM 2.2 : ovs-agent (OVMSA-2010-0015)");
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

  - Update changelog, fill CVE number.

  - Fix config-file access mode issue.

  - Fix file access vulnerability [orabug 10142417]
    (CVE-2010-3582)

  - Fix local privilege escalation [orabug 10142476]
    (CVE-2010-3584)

  - Fix ovs agent command injection [orabug 10146644]
    (CVE-2010-3585)

  - Fix validate master ip command injection [orabug
    10142448] (CVE-2010-3583)

  - Add excutable mode to utils/upgrade.py."
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2010-October/000056.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f5790f09"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ovs-agent package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Oracle VM Server Virtual Server Agent Command Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:ovs-agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/15");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"OVS2.2", reference:"ovs-agent-2.3-42")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ovs-agent");
}
