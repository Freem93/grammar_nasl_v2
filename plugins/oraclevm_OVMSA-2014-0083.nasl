#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2014-0083.
#

include("compat.inc");

if (description)
{
  script_id(80008);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2013-6435");
  script_bugtraq_id(71558);
  script_osvdb_id(115601);

  script_name(english:"OracleVM 3.3 : rpm (OVMSA-2014-0083)");
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

  - Fix race condidition where unchecked data is exposed in
    the file system (CVE-2013-6435)(#1163059)

  - Fix thinko in the non-root python byte-compilation fix

  - Byte-compile versioned python libdirs in non-root prefix
    too (#868332)

  - Fix segfault on rpmdb addition when header unload fails
    (#706935)

  - Add a compat mode for enabling legacy rpm scriptlet
    error behavior (#963724)

  - Fix build-time double-free on file capability processing
    (#904818)

  - Fix include-directive getting processed on false branch
    (#920190)

  - Bring back --fileid in the man page with description of
    the id (#804049)

  - Fix missing error on --import on bogus key file
    (#869667)

  - Add DWARF 4 support to debugedit (#858731)

  - Add better error handling to patch for bug

  - Fix memory corruption on multikey PGP packets/armors
    (#829621)

  - Handle identical binaries for debug-info (#727872)

  - Fix typos in Japanese rpm man page (#845065)

  - Document -D and -E options in man page (#845063)

  - Add --setperms and --setuids to the man page (#839126)

  - Update man page that SHA256 is also used for file digest
    (#804049)

  - Remove --fileid from man page to get rid of md5

  - Remove -s from patch calls (#773503)

  - Force _host_vendor to redhat to better match toolchain
    (#743229)

  - Backport reloadConfig for Python API (#825147)

  - Support for dpkg-style sorting of tilde in
    version/release (#825087)

  - Fix explicit directory %attr when %defattr is active
    (#730473)

  - Don't load keyring if signature checking is disabled
    (#664696)

  - Retry read to fix rpm2cpio with pipe as stdin (#802839)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2014-December/000246.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8451a6f3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rpm / rpm-libs / rpm-python packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:rpm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:rpm-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
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
if (! ereg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"rpm-4.8.0-38.el6_6")) flag++;
if (rpm_check(release:"OVS3.3", reference:"rpm-libs-4.8.0-38.el6_6")) flag++;
if (rpm_check(release:"OVS3.3", reference:"rpm-python-4.8.0-38.el6_6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rpm / rpm-libs / rpm-python");
}
