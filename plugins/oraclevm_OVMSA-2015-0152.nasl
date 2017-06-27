#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2015-0152.
#

include("compat.inc");

if (description)
{
  script_id(87232);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2015-5312", "CVE-2015-7497", "CVE-2015-7498", "CVE-2015-7499", "CVE-2015-7500", "CVE-2015-7941", "CVE-2015-7942", "CVE-2015-8242", "CVE-2015-8317");
  script_osvdb_id(121175, 130292, 130535, 130536, 130538, 130539, 130543, 130641, 130642);

  script_name(english:"OracleVM 3.3 : libxml2 (OVMSA-2015-0152)");
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

  - Update doc/redhat.gif in tarball

  - Add libxml2-oracle-enterprise.patch and update logos in
    tarball

  - Fix a series of CVEs (rhbz#1286495)

  - CVE-2015-7941 Cleanup conditional section error handling

  - CVE-2015-8317 Fail parsing early on if encoding
    conversion failed

  - CVE-2015-7942 Another variation of overflow in
    Conditional sections

  - CVE-2015-7942 Fix an error in previous Conditional
    section patch

  - Fix parsing short unclosed comment uninitialized access

  - CVE-2015-7498 Avoid processing entities after encoding
    conversion failures

  - CVE-2015-7497 Avoid an heap buffer overflow in
    xmlDictComputeFastQKey

  - CVE-2015-5312 Another entity expansion issue

  - CVE-2015-7499 Add xmlHaltParser to stop the parser

  - CVE-2015-7499 Detect incoherency on GROW

  - CVE-2015-7500 Fix memory access error due to incorrect
    entities boundaries

  - CVE-2015-8242 Buffer overead with HTML parser in push
    mode

  - Libxml violates the zlib interface and crashes"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2015-December/000399.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1268d569"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 / libxml2-python packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/08");
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
if (rpm_check(release:"OVS3.3", reference:"libxml2-2.7.6-20.0.1.el6_7.1")) flag++;
if (rpm_check(release:"OVS3.3", reference:"libxml2-python-2.7.6-20.0.1.el6_7.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2 / libxml2-python");
}
