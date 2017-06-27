#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(87550);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/22 15:46:34 $");

  script_cve_id("CVE-2014-8484", "CVE-2014-8485", "CVE-2014-8501", "CVE-2014-8502", "CVE-2014-8503", "CVE-2014-8504", "CVE-2014-8737", "CVE-2014-8738");

  script_name(english:"Scientific Linux Security Update : binutils on SL7.x x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple buffer overflow flaws were found in the libbdf library used
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

  - Binary files started by the system loader could lack the
    Relocation Read-Only (RELRO) protection even though it
    was explicitly requested when the application was built.
    This bug has been fixed on multiple architectures.
    Applications and all dependent object files, archives,
    and libraries built with an alpha or beta version of
    binutils should be rebuilt to correct this defect.

  - The ld linker on 64-bit PowerPC now correctly checks the
    output format when asked to produce a binary in another
    format than PowerPC.

  - An important variable that holds the symbol table for
    the binary being debugged has been made persistent, and
    the objdump utility on 64-bit PowerPC is now able to
    access the needed information without reading an invalid
    memory region.

  - Undesirable runtime relocations described in
    SLBA-2015:0974.

The update adds these enhancements :

  - New hardware instructions of the IBM z Systems z13 are
    now supported by assembler, disassembler, and linker, as
    well as Single Instruction, Multiple Data (SIMD)
    instructions.

  - Expressions of the form: 'FUNC@localentry' to refer to
    the local entry point for the FUNC function (if defined)
    are now supported by the PowerPC assembler. These are
    required by the ELFv2 ABI on the little-endian variant
    of IBM Power Systems."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=13035
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f944b113"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected binutils, binutils-debuginfo and / or
binutils-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"binutils-2.23.52.0.1-55.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"binutils-debuginfo-2.23.52.0.1-55.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"binutils-devel-2.23.52.0.1-55.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
