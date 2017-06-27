#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0050.
#

include("compat.inc");

if (description)
{
  script_id(91155);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2012-1571", "CVE-2014-3538", "CVE-2014-3587", "CVE-2014-3710", "CVE-2014-8116", "CVE-2014-8117", "CVE-2014-9620", "CVE-2014-9653");
  script_bugtraq_id(52225, 68348, 69325, 70807, 71692, 71700, 71715, 72516);
  script_osvdb_id(79681, 104208, 113614, 115923, 115924, 117591, 118387);

  script_name(english:"OracleVM 3.3 / 3.4 : file (OVMSA-2016-0050)");
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

  - fix CVE-2014-3538 (unrestricted regular expression
    matching)

  - fix #1284826 - try to read ELF header to detect
    corrupted one

  - fix #1263987 - fix bugs found by coverity in the patch

  - fix CVE-2014-3587 (incomplete fix for CVE-2012-1571)

  - fix CVE-2014-3710 (out-of-bounds read in elf note
    headers)

  - fix CVE-2014-8116 (multiple DoS issues (resource
    consumption))

  - fix CVE-2014-8117 (denial of service issue (resource
    consumption))

  - fix CVE-2014-9620 (limit the number of ELF notes
    processed)

  - fix CVE-2014-9653 (malformed elf file causes access to
    uninitialized memory)

  - fix #809898 - add support for detection of Python 2.7
    byte-compiled files

  - fix #1263987 - fix coredump execfn detection on ppc64
    and s390

  - fix #966953 - include msooxml file in magic.mgc
    generation

  - fix #966953 - increate the strength of MSOOXML magic
    patterns

  - fix #1169509 - add support for Java 1.7 and 1.8

  - fix #1243650 - comment out too-sensitive Pascal magic

  - fix #1080453 - remove .orig files from magic directory

  - fix #1161058 - add support for EPUB

  - fix #1162149 - remove parts of patches patching .orig
    files

  - fix #1154802 - fix detection of zip files containing
    file named mime

  - fix #1246073 - fix detection UTF8 and UTF16 encoded XML
    files

  - fix #1263987 - add new execfn to coredump output to show
    the real name of executable which generated the coredump

  - fix #809898 - add support for detection of Python
    3.2-3.5 byte-compiled files

  - fix #966953 - backport support for MSOOXML"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2016-May/000460.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2016-May/000464.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected file / file-libs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:file-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/16");
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
if (! ereg(pattern:"^OVS" + "(3\.3|3\.4)" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3 / 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"file-5.04-30.el6")) flag++;
if (rpm_check(release:"OVS3.3", reference:"file-libs-5.04-30.el6")) flag++;

if (rpm_check(release:"OVS3.4", reference:"file-5.04-30.el6")) flag++;
if (rpm_check(release:"OVS3.4", reference:"file-libs-5.04-30.el6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "file / file-libs");
}
