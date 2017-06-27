#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63680);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/01/24 13:51:03 $");

  script_cve_id("CVE-2012-5530");

  script_name(english:"SuSE 10 Security Update : pcp (ZYPP Patch Number 8421)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"pcp was updated to version 3.6.10 which fixes security issues and also
brings a lot of new features.

  - Update to pcp-3.6.10. o Transition daemons to run under
    an unprivileged account. o Fixes for security advisory
    CVE-2012-5530: tmpfile flaws; (bnc#782967). o Fix pcp(1)
    command short-form pmlogger reporting. o Fix pmdalogger
    error handling for directory files. o Fix pmstat
    handling of odd corner case in CPU metrics. o Correct
    the python ctype used for pmAtomValue 32bit ints. o Add
    missing RPM spec dependency for python-ctypes. o
    Corrections to pmdamysql metrics units. o Add pmdamysql
    slave status metrics. o Improve pmcollectl error
    messages. o Parameterize pmcollectl CPU counts in
    interrupt subsys. o Fix generic RPM packaging for
    powerpc builds. o Fix python API use of reentrant libpcp
    string routines. o Python code backporting for RHEL5 in
    qa and pmcollectl. o Fix edge cases in capturing
    interrupt error counts.

  - Update to pcp-3.6.9. o Python wrapper for the pmimport
    API o Make sar2pcp work with the sysstat versions from
    RHEL5, RHEL6, and all recent Fedora versions (which is
    almost all current versions of sysstat verified). o
    Added a number of additional metrics into the importer
    for people starting to use it to analyse sar data from
    real customer incidents. o Rework use of C99 'restrict'
    keyword in pmdalogger (Debian bug: 689552) o Alot of
    work on the PCP QA suite, special thanks to Tomas
    Dohnalek for all his efforts there. o Win32 build
    updates o Add 'raw' disk active metrics so that existing
    tools like iostat can be emulated o Allow sar2pcp to
    accept XML input directly (.xml suffix), allowing it to
    not have to run on the same platform as the sadc/sadf
    that originally generated it. o Add PMI error codes into
    the PCP::LogImport perl module. o Fix a typo in pmiUnits
    man page synopsis section o Resolve pmdalinux ordering
    issue in NUMA/CPU indom setup (Redhat bug: 858384) o
    Remove unused pmcollectl imports (Redhat bug: 863210) o
    Allow event traces to be used in libpcp interpolate mode

  - Update to pcp-3.6.8. o Corrects the disk/partition
    identification for the MMC driver, which makes disk
    indom handling correct on the Raspberry Pi
    (http://www.raspberrypi.org/) o Several minor/basic
    fixes for pmdaoracle. o Improve pmcollectl
    compatibility. o Make a few clarifications to
    pmcollectl.1. o Improve python API test coverage. o
    Numerous updates to the test suite in general. o Allow
    pmda Install scripts to specify own dso name again. o
    Reconcile spec file differences between PCP flavours. o
    Fix handling of multiple contexts with a remote
    namespace. o Core socket interface abstractions to
    support NSS (later). o Fix man page SYNOPSIS section for
    pmUnpackEventRecords. o Add --disable-shared build
    option for static builds.

  - Update to pcp-3.6.6. o Added the python PMAPI bindings
    and an initial python client in pmcollectl. Separate,
    new package exists for python libs for those platforms
    that split out packages (rpm, deb). o Added a
    pcp-testsuite package for those platforms that might
    want this (rpm, deb again, mainly) o Re-introduced the
    pcp/qa subdirectory in pcp and deprecated the external
    pcpqa git tree. o Fix potential buffer overflow in
    pmlogger host name handling. o Reworked the configure
    --prefix handling to be more like the rest of the open
    source world. o Ensure the __pmDecodeText ident
    parameter is always set Resolves Red Hat bugzilla bug
    #841306."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5530.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8421.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:4, reference:"permissions-2013.1.7-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"libpcp3-3.6.10-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"pcp-3.6.10-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"pcp-import-iostat2pcp-3.6.10-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"pcp-import-mrtg2pcp-3.6.10-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"pcp-import-sar2pcp-3.6.10-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"pcp-import-sheet2pcp-3.6.10-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"perl-PCP-LogImport-3.6.10-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"perl-PCP-LogSummary-3.6.10-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"perl-PCP-MMV-3.6.10-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"perl-PCP-PMDA-3.6.10-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"permissions-2013.1.7-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else exit(0, "The host is not affected.");
