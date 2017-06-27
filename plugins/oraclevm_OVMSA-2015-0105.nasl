#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2015-0105.
#

include("compat.inc");

if (description)
{
  script_id(85146);
  script_version("$Revision: 2.11 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2014-8500", "CVE-2015-1349", "CVE-2015-4620", "CVE-2015-5477");
  script_bugtraq_id(71590, 72673, 75588);
  script_osvdb_id(115524, 118546, 124233, 125438);

  script_name(english:"OracleVM 3.3 : bind (OVMSA-2015-0105)");
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

  - Fix (CVE-2015-5477)

  - Fix (CVE-2015-4620)

  - Resolves: 1215687 - DNS resolution failure in high load
    environment with SERVFAIL and 'out of memory/success' in
    the log

  - Fix (CVE-2015-1349)

  - Enable RPZ-NSIP and RPZ-NSDNAME during compilation
    (#1176476)

  - Fix race condition when using isc__begin_beginexclusive
    (#1175321)

  - Sanitize SDB API to better handle database errors
    (#1146893)

  - Fix CVE-2014-8500 (#1171974)

  - Fix RRL slip behavior when set to 1 (#1112356)

  - Fix issue causing bind to hang after reload if using
    DYNDB (#1142152)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2015-July/000353.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bind-libs / bind-utils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/31");
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
if (rpm_check(release:"OVS3.3", reference:"bind-libs-9.8.2-0.37.rc1.el6_7.2")) flag++;
if (rpm_check(release:"OVS3.3", reference:"bind-utils-9.8.2-0.37.rc1.el6_7.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind-libs / bind-utils");
}
