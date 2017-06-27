#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2009-0018.
#

include("compat.inc");

if (description)
{
  script_id(79462);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2007-6284", "CVE-2008-3281", "CVE-2008-3529", "CVE-2008-4225", "CVE-2008-4226", "CVE-2009-2414", "CVE-2009-2416");
  script_bugtraq_id(27248, 30783, 31126, 32326, 32331, 36010);

  script_name(english:"OracleVM 2.1 : libxml2 (OVMSA-2009-0018)");
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

  - Add bug347316.patch to backport fix for bug#347316 from
    upstream version

  - Add libxml2-enterprise.patch and update logos in tarball

  - Fix a couple of crash (CVE-2009-2414, CVE-2009-2416)

  - Resolves: rhbz#515236

  - two patches for size overflows problems (CVE-2008-4225,
    CVE-2008-4226)

  - Resolves: rhbz#470474

  - Patch to fix an entity name copy buffer overflow
    (CVE-2008-3529)

  - Resolves: rhbz#461023

  - Better fix for (CVE-2008-3281)

  - Resolves: rhbz#458095

  - change the patch for CVE-2008-3281 due to ABI issues

  - Resolves: rhbz#458095

  - Patch to fix recursive entities handling (CVE-2008-3281)

  - Resolves: rhbz#458095

  - Patch to fix UTF-8 decoding problem (CVE-2007-6284)

  - Resolves: rhbz#425933"
  );
  # http://svn.gnome.org/viewvc/libxml2/trunk/xmlschemas.c?r1=3470&amp;r2=3503
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b1b9935"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2009-August/000029.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9315a626"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 / libxml2-python packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/14");
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
if (rpm_check(release:"OVS2.1", reference:"libxml2-2.6.26-2.1.2.8.0.2")) flag++;
if (rpm_check(release:"OVS2.1", reference:"libxml2-python-2.6.26-2.1.2.8.0.2")) flag++;

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
