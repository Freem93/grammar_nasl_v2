#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2079. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86928);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/01/06 16:01:53 $");

  script_cve_id("CVE-2014-8484", "CVE-2014-8485", "CVE-2014-8501", "CVE-2014-8502", "CVE-2014-8503", "CVE-2014-8504", "CVE-2014-8737", "CVE-2014-8738");
  script_osvdb_id(113682, 113735, 113825, 113828, 114037, 114039, 114129, 114209);
  script_xref(name:"RHSA", value:"2015:2079");

  script_name(english:"RHEL 7 : binutils (RHSA-2015:2079)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated binutils packages that fix multiple security issues, several
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
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8484.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8485.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8501.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8502.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8503.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8504.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8737.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8738.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://rhn.redhat.com/errata/RHBA-2015-0974.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-2079.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected binutils, binutils-debuginfo and / or
binutils-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:binutils-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:2079";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"binutils-2.23.52.0.1-55.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"binutils-2.23.52.0.1-55.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"binutils-debuginfo-2.23.52.0.1-55.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"binutils-devel-2.23.52.0.1-55.el7")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils / binutils-debuginfo / binutils-devel");
  }
}
