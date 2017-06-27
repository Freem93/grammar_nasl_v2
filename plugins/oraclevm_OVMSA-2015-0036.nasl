#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2015-0036.
#

include("compat.inc");

if (description)
{
  script_id(81967);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2012-5669", "CVE-2014-9657", "CVE-2014-9658", "CVE-2014-9660", "CVE-2014-9661", "CVE-2014-9663", "CVE-2014-9664", "CVE-2014-9667", "CVE-2014-9669", "CVE-2014-9670", "CVE-2014-9671", "CVE-2014-9673", "CVE-2014-9674", "CVE-2014-9675");
  script_bugtraq_id(57041, 72986);
  script_osvdb_id(88819, 114332, 114333, 114354, 114619, 114621, 114961, 114962, 114964, 114965, 115073, 115075, 115098);

  script_name(english:"OracleVM 3.3 : freetype (OVMSA-2015-0036)");
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

  - Fixes (CVE-2014-9657)

  - Check minimum size of `record_size'.

  - Fixes (CVE-2014-9658)

  - Use correct value for minimum table length test.

  - Fixes (CVE-2014-9675)

  - New macro that checks one character more than `strncmp'.

  - Fixes (CVE-2014-9660)

  - Check `_BDF_GLYPH_BITS'.

  - Fixes (CVE-2014-9661)

  - Initialize `face->ttf_size'.

  - Always set `face->ttf_size' directly.

  - Exclusively use the `truetype' font driver for loading
    the font contained in the `sfnts' array.

  - Fixes (CVE-2014-9663)

  - Fix order of validity tests.

  - Fixes (CVE-2014-9664)

  - Add another boundary testing.

  - Fix boundary testing.

  - Fixes (CVE-2014-9667)

  - Protect against addition overflow.

  - Fixes (CVE-2014-9669)

  - Protect against overflow in additions and
    multiplications.

  - Fixes (CVE-2014-9670)

  - Add sanity checks for row and column values.

  - Fixes (CVE-2014-9671)

  - Check `size' and `offset' values.

  - Fixes (CVE-2014-9673)

  - Fix integer overflow by a broken POST table in
    resource-fork.

  - Fixes (CVE-2014-9674)

  - Fix integer overflow by a broken POST table in
    resource-fork.

  - Additional overflow check in the summation of POST
    fragment lengths.

  - Work around behaviour of X11's `pcfWriteFont' and
    `pcfReadFont' functions

  - Resolves: #1197737

  - Fix (CVE-2012-5669) (Use correct array size for checking
    `glyph_enc')

  - Resolves: #903543"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2015-March/000288.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?22fbb5cd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freetype package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:freetype");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/20");
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
if (rpm_check(release:"OVS3.3", reference:"freetype-2.3.11-15.el6_6.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freetype");
}
