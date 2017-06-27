#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2015-0027.
#

include("compat.inc");

if (description)
{
  script_id(81695);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2015-2044", "CVE-2015-2045");
  script_bugtraq_id(72954, 72955);
  script_osvdb_id(119166, 119202);

  script_name(english:"OracleVM 2.2 : xen (OVMSA-2015-0027)");
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

  - XSA-122: pre-fill structures for certain
    HYPERVISOR_xen_version sub-ops (Jan Beulich) [20588670]
    [CVE-2015-2045]

  - XSA-121: return all ones on wrong-sized reads of system
    device I/O ports (Jan Beulich) [20588358]
    [CVE-2015-2044]"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2015-March/000280.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?50427ec3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-pvhvm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/09");
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
if (rpm_check(release:"OVS2.2", reference:"xen-3.4.0-0.2.21.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"xen-64-3.4.0-0.2.21.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"xen-debugger-3.4.0-0.2.21.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"xen-devel-3.4.0-0.2.21.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"xen-pvhvm-devel-3.4.0-0.2.21.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"xen-tools-3.4.0-0.2.21.el5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-64 / xen-debugger / xen-devel / xen-pvhvm-devel / etc");
}
