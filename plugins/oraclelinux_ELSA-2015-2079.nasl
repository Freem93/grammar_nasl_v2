#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:2079 and 
# Oracle Linux Security Advisory ELSA-2015-2079 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(87018);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/20 14:21:44 $");

  script_cve_id("CVE-2014-8484", "CVE-2014-8485", "CVE-2014-8501", "CVE-2014-8502", "CVE-2014-8503", "CVE-2014-8504", "CVE-2014-8737", "CVE-2014-8738");
  script_osvdb_id(113682, 113735, 113825, 113828, 114037, 114039, 114129, 114209);
  script_xref(name:"RHSA", value:"2015:2079");

  script_name(english:"Oracle Linux 7 : binutils (ELSA-2015-2079)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:2079 :

Updated binutils packages that fix multiple security issues, several
bugs, and add various enhancements are now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The binutils packages provide a set of binary utilities.

Multiple buffer overflow flaws were found in the libbdf library used
by various binutils utilities. If a user were tricked into processing
a specially crafted file with an application using the libbdf library,
it could cause the application to crash or, potentially, execute
arbitrary code. (CVE-2014-8485, CVE-2014-8501, CVE-2014-8502,
CVE-2014-8503, CVE-2014-8504, CVE-2014-8738)

An integer overflow flaw was found in the libbdf library used by
various binutils utilities. If a user were tricked into processing a
specially crafted file with an application using the libbdf library,
it could cause the application to crash. (CVE-2014-8484)

A directory traversal flaw was found in the strip and objcopy
utilities. A specially crafted file could cause strip or objdump to
overwrite an arbitrary file writable by the user running either of
these utilities. (CVE-2014-8737)

This update fixes the following bugs :

* Binary files started by the system loader could lack the Relocation
Read-Only (RELRO) protection even though it was explicitly requested
when the application was built. This bug has been fixed on multiple
architectures. Applications and all dependent object files, archives,
and libraries built with an alpha or beta version of binutils should
be rebuilt to correct this defect. (BZ#1200138, BZ#1175624)

* The ld linker on 64-bit PowerPC now correctly checks the output
format when asked to produce a binary in another format than PowerPC.
(BZ#1226864)

* An important variable that holds the symbol table for the binary
being debugged has been made persistent, and the objdump utility on
64-bit PowerPC is now able to access the needed information without
reading an invalid memory region. (BZ#1172766)

* Undesirable runtime relocations described in RHBA-2015:0974.
(BZ#872148)

The update adds these enhancements :

* New hardware instructions of the IBM z Systems z13 are now supported
by assembler, disassembler, and linker, as well as Single Instruction,
Multiple Data (SIMD) instructions. (BZ#1182153)

* Expressions of the form: 'FUNC@localentry' to refer to the local
entry point for the FUNC function (if defined) are now supported by
the PowerPC assembler. These are required by the ELFv2 ABI on the
little-endian variant of IBM Power Systems. (BZ#1194164)

All binutils users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add these
enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-November/005576.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected binutils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:binutils-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"binutils-2.23.52.0.1-55.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"binutils-devel-2.23.52.0.1-55.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils / binutils-devel");
}
