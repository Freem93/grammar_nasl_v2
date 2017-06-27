#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2009-0027.
#

include("compat.inc");

if (description)
{
  script_id(79467);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/24 13:36:53 $");

  script_cve_id("CVE-2008-2327", "CVE-2009-2285", "CVE-2009-2347");
  script_bugtraq_id(30832, 35451, 35652);
  script_osvdb_id(55265, 55821, 55822);

  script_name(english:"OracleVM 2.1 : libtiff (OVMSA-2009-0027)");
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

  - Fix buffer overrun risks caused by unchecked integer
    overflow (CVE-2009-2347) Resolves: #507725

  - Fix some more LZW decoding vulnerabilities
    (CVE-2009-2285) Resolves: #507725

  - Update upstream URL

  - Use -fno-strict-aliasing per rpmdiff recommendation

  - Fix LZW decoding vulnerabilities (CVE-2008-2327)
    Resolves: #458812

  - Remove sgi2tiff.1 and tiffsv.1, since they are for
    programs we don't ship Resolves: #460120"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2009-October/000037.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2af78c77"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtiff / libtiff-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:libtiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^OVS" + "2\.1" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 2.1", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);

flag = 0;
if (rpm_check(release:"OVS2.1", reference:"libtiff-3.8.2-7.el5_3.4")) flag++;
if (rpm_check(release:"OVS2.1", reference:"libtiff-devel-3.8.2-7.el5_3.4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff / libtiff-devel");
}
