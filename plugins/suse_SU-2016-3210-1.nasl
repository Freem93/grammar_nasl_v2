#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:3210-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(96078);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/01/26 14:48:47 $");

  script_cve_id("CVE-2016-9893", "CVE-2016-9895", "CVE-2016-9897", "CVE-2016-9898", "CVE-2016-9899", "CVE-2016-9900", "CVE-2016-9901", "CVE-2016-9902", "CVE-2016-9904", "CVE-2016-9905");
  script_osvdb_id(148666, 148667, 148668, 148693, 148695, 148696, 148697, 148698, 148699, 148700, 148701, 148704, 148705, 148706, 148707, 148708, 148709, 148710, 148711);

  script_name(english:"SUSE SLES11 Security Update : MozillaFirefox (SUSE-SU-2016:3210-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaFirefox 45 ESR was updated to 45.6 to fix the following 
issues :

  - MFSA 2016-95/CVE-2016-9897: Memory corruption in libGLES

  - MFSA 2016-95/CVE-2016-9901: Data from Pocket server
    improperly sanitized before execution

  - MFSA 2016-95/CVE-2016-9898: Use-after-free in Editor
    while manipulating DOM subtrees

  - MFSA 2016-95/CVE-2016-9899: Use-after-free while
    manipulating DOM events and audio elements

  - MFSA 2016-95/CVE-2016-9904: Cross-origin information
    leak in shared atoms

  - MFSA 2016-95/CVE-2016-9905: Crash in
    EnumerateSubDocuments

  - MFSA 2016-95/CVE-2016-9895: CSP bypass using marquee tag

  - MFSA 2016-95/CVE-2016-9900: Restricted external
    resources can be loaded by SVG images through data URLs

  - MFSA 2016-95/CVE-2016-9893: Memory safety bugs fixed in
    Firefox 50.1 and Firefox ESR 45.6

  - MFSA 2016-95/CVE-2016-9902: Pocket extension does not
    validate the origin of events Please see
    https://www.mozilla.org/en-US/security/advisories/mfsa20
    16-95/ for more information. Also the following bug was
    fixed :

  - Fix fontconfig issue (bsc#1000751) on 32bit systems as
    well.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-95/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9893.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9895.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9897.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9898.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9899.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9900.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9901.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9902.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9904.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9905.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20163210-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?44c98d36"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 5:zypper in -t patch
sleclo50sp3-MozillaFirefox-12903=1

SUSE Manager Proxy 2.1:zypper in -t patch
slemap21-MozillaFirefox-12903=1

SUSE Manager 2.1:zypper in -t patch sleman21-MozillaFirefox-12903=1

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-MozillaFirefox-12903=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-MozillaFirefox-12903=1

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-MozillaFirefox-12903=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-MozillaFirefox-12903=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-MozillaFirefox-12903=1

SUSE Linux Enterprise Debuginfo 11-SP3:zypper in -t patch
dbgsp3-MozillaFirefox-12903=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"MozillaFirefox-45.6.0esr-62.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"MozillaFirefox-translations-45.6.0esr-62.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"MozillaFirefox-45.6.0esr-62.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"MozillaFirefox-translations-45.6.0esr-62.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox");
}
