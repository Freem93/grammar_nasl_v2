#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0077.
#

include("compat.inc");

if (description)
{
  script_id(91753);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/02/14 17:23:20 $");

  script_cve_id("CVE-2011-3378", "CVE-2012-0060", "CVE-2012-0061", "CVE-2012-0815", "CVE-2013-6435");
  script_bugtraq_id(49799, 52865, 71558);
  script_osvdb_id(75930, 75931, 81009, 81010, 81011, 115601);

  script_name(english:"OracleVM 3.2 : rpm (OVMSA-2016-0077)");
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

  - Add missing files in /usr/share/doc/

  - Fix warning when applying the patch for #1163057

  - Fix race condidition where unchecked data is exposed in
    the file system (CVE-2013-6435)(#1163057)

  - Fix segfault on rpmdb addition when header unload fails
    (#706935)

  - Fix segfault on invalid OpenPGP packet (#743203)

  - Account for excludes and hardlinks wrt payload max size
    (#716853)

  - Fix payload size tag generation on big-endian systems
    (#648516)

  - Track all install failures within a transaction
    (#671194)

  - fix changelog (bug #707677 is actually #808547)

  - Document -D and -E options in man page (#814602)

  - Require matching arch for freshen on colored
    transactions (#813282)

  - Add DWARF 3 and 4 support to debugedit (#808547)

  - No longer add \n to group tag in Python bindings
    (#783451)

  - Fix typos in Japanese rpm man page (#760552)

  - Bump Geode compatibility up to i686 (#620570)

  - Proper region tag validation on package/header read
    (CVE-2012-0060)

  - Double-check region size against header size
    (CVE-2012-0061)

  - Validate negated offsets too in headerVerifyInfo
    (CVE-2012-0815)

  - Revert fix for #740291, too many packages rely on the
    broken behavior

  - Add support for XZ-compressed sources and patches to
    rpmbuild (#620674)

  - Avoid unnecessary assert-death when closing NULL fd
    (#573043)

  - Add scriptlet error notification callbacks (#533831)

  - Honor --noscripts for pre- and posttrans scriptlets too
    (#740345)

  - Avoid bogus error on printing empty ds from python
    (#628883)

  - File conflicts correctness & consistency fixes (#740291)

  - Create the directory used for transaction lock if
    necessary (#510469)

  - Only enforce default umask during transaction (#673821)

  - fix thinko in the CVE backport

  - fix CVE-2011-3378 (#742157)

  - accept windows cr/lf line endings in gpg keys (#530212)

  - Backport multilib ordering fixes from rpm 4.8.x
    (#641892)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2016-June/000492.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:popt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:rpm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:rpm-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/22");
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
if (! ereg(pattern:"^OVS" + "3\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.2", reference:"popt-1.10.2.3-36.0.1.el5_11")) flag++;
if (rpm_check(release:"OVS3.2", reference:"rpm-4.4.2.3-36.0.1.el5_11")) flag++;
if (rpm_check(release:"OVS3.2", reference:"rpm-libs-4.4.2.3-36.0.1.el5_11")) flag++;
if (rpm_check(release:"OVS3.2", reference:"rpm-python-4.4.2.3-36.0.1.el5_11")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "popt / rpm / rpm-libs / rpm-python");
}
