#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2015-0102.
#

include("compat.inc");

if (description)
{
  script_id(85143);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2014-9297", "CVE-2014-9298", "CVE-2015-1798", "CVE-2015-1799", "CVE-2015-3405");
  script_bugtraq_id(72583, 72584, 73950, 73951, 74045);
  script_osvdb_id(116071, 116072, 120350, 120351, 120524);
  script_xref(name:"TRA", value:"TRA-2015-04");

  script_name(english:"OracleVM 3.3 : ntp (OVMSA-2015-0102)");
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

  - reject packets without MAC when authentication is
    enabled (CVE-2015-1798)

  - protect symmetric associations with symmetric key
    against DoS attack (CVE-2015-1799)

  - fix generation of MD5 keys with ntp-keygen on big-endian
    systems (CVE-2015-3405)

  - log when stepping clock for leap second or ignoring it
    with -x (#1204625)

  - fix typos in ntpd man page (#1194463)

  - validate lengths of values in extension fields
    (CVE-2014-9297)

  - drop packets with spoofed source address ::1
    (CVE-2014-9298)

  - add nanosecond support to SHM refclock (#1117704)

  - allow creating all SHM segments with owner-only access
    (#1122015)

  - allow symmetric keys up to 32 bytes again (#1053551)

  - fix calculation of root dispersion (#1045376)

  - fix crash in ntpq mreadvar command (#1165141)

  - don't step clock for leap second with -x option
    (#1190619)

  - don't drop packets with source port below 123 (#1171630)

  - use larger RSA exponent in ntp-keygen (#1184421)

  - refresh peers on routing updates (#1193850)

  - increase memlock limit again (#1053568)

  - warn when monitor can't be disabled due to limited
    restrict (#1166596)

  - improve documentation of restrict command (#1069019)

  - update logconfig documentation for patched default
    (#1193849)

  - don't build ntpsnmpd (#995134)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2015-July/000352.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2015-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ntp / ntpdate packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:ntpdate");
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
if (rpm_check(release:"OVS3.3", reference:"ntp-4.2.6p5-5.el6")) flag++;
if (rpm_check(release:"OVS3.3", reference:"ntpdate-4.2.6p5-5.el6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp / ntpdate");
}
