#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(64188);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/25 23:52:00 $");

  script_cve_id("CVE-2012-3418", "CVE-2012-3419", "CVE-2012-3420", "CVE-2012-3421", "CVE-2012-5530");

  script_name(english:"SuSE 11.2 Security Update : pcp (SAT Patch Number 7221)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"pcp was updated to version 3.6.10 which fixes security issues and also
brings a lot of new features.

  - Update to pcp-3.6.10.

  - Transition daemons to run under an unprivileged account.

  - Fixes for security advisory CVE-2012-5530: tmpfile
    flaws;. (bnc#782967)

  - Fix pcp(1) command short-form pmlogger reporting.

  - Fix pmdalogger error handling for directory files.

  - Fix pmstat handling of odd corner case in CPU metrics.

  - Correct the python ctype used for pmAtomValue 32bit
    ints.

  - Add missing RPM spec dependency for python-ctypes.

  - Corrections to pmdamysql metrics units.

  - Add pmdamysql slave status metrics.

  - Improve pmcollectl error messages.

  - Parameterize pmcollectl CPU counts in interrupt subsys.

  - Fix generic RPM packaging for powerpc builds.

  - Fix python API use of reentrant libpcp string routines.

  - Python code backporting for RHEL5 in qa and pmcollectl.

  - Fix edge cases in capturing interrupt error counts.

  - Update to pcp-3.6.9.

  - Python wrapper for the pmimport API

  - Make sar2pcp work with the sysstat versions from RHEL5,
    RHEL6, and all recent Fedora versions (which is almost
    all current versions of sysstat verified).

  - Added a number of additional metrics into the importer
    for people starting to use it to analyse sar data from
    real customer incidents.

  - Rework use of C99 'restrict' keyword in pmdalogger
    (Debian bug: 689552)

  - Alot of work on the PCP QA suite, special thanks to
    Tomas Dohnalek for all his efforts there.

  - Win32 build updates

  - Add 'raw' disk active metrics so that existing tools
    like iostat can be emulated

  - Allow sar2pcp to accept XML input directly (.xml
    suffix), allowing it to not have to run on the same
    platform as the sadc/sadf that originally generated it.

  - Add PMI error codes into the PCP::LogImport perl module.

  - Fix a typo in pmiUnits man page synopsis section

  - Resolve pmdalinux ordering issue in NUMA/CPU indom setup
    (Redhat bug: 858384)

  - Remove unused pmcollectl imports (Redhat bug: 863210)

  - Allow event traces to be used in libpcp interpolate mode

  - Update to pcp-3.6.8.

  - Corrects the disk/partition identification for the MMC
    driver, which makes disk indom handling correct on the
    Raspberry Pi (http://www.raspberrypi.org/)

  - Several minor/basic fixes for pmdaoracle.

  - Improve pmcollectl compatibility.

  - Make a few clarifications to pmcollectl.1.

  - Improve python API test coverage.

  - Numerous updates to the test suite in general.

  - Allow pmda Install scripts to specify own dso name
    again.

  - Reconcile spec file differences between PCP flavours.

  - Fix handling of multiple contexts with a remote
    namespace.

  - Core socket interface abstractions to support NSS
    (later).

  - Fix man page SYNOPSIS section for pmUnpackEventRecords.

  - Add --disable-shared build option for static builds.

  - Update to pcp-3.6.6.

  - Added the python PMAPI bindings and an initial python
    client in pmcollectl. Separate, new package exists for
    python libs for those platforms that split out packages
    (rpm, deb).

  - Added a pcp-testsuite package for those platforms that
    might want this (rpm, deb again, mainly)

  - Re-introduced the pcp/qa subdirectory in pcp and
    deprecated the external pcpqa git tree.

  - Fix potential buffer overflow in pmlogger host name
    handling.

  - Reworked the configure --prefix handling to be more like
    the rest of the open source world.

  - Ensure the __pmDecodeText ident parameter is always set
    Resolves Red Hat bugzilla bug #841306."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=732763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=775009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=775010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=775011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=775013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=782967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3418.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3419.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3420.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3421.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5530.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 7221.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:permissions");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"permissions-2013.1.7-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"permissions-2013.1.7-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"permissions-2013.1.7-0.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
