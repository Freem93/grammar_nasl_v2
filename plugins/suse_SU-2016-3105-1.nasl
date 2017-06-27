#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:3105-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(95797);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/01/24 14:51:33 $");

  script_cve_id("CVE-2016-5285", "CVE-2016-5290", "CVE-2016-5291", "CVE-2016-5296", "CVE-2016-5297", "CVE-2016-9064", "CVE-2016-9066", "CVE-2016-9074", "CVE-2016-9079");
  script_osvdb_id(147338, 147342, 147343, 147345, 147352, 147362, 147375, 147376, 147377, 147378, 147379, 147380, 147381, 147382, 147383, 147384, 147385, 147386, 147521, 147993);

  script_name(english:"SUSE SLES11 Security Update : MozillaFirefox, mozilla-nss (SUSE-SU-2016:3105-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for MozillaFirefox, mozilla-nss fixes security issues and
bugs. The following vulnerabilities were fixed in Firefox ESR 45.5.1
(bsc#1009026) :

  - CVE-2016-9079: Use-after-free in SVG Animation
    (bsc#1012964 MFSA 2016-92)

  - CVE-2016-5297: Incorrect argument length checking in
    JavaScript (bsc#1010401)

  - CVE-2016-9066: Integer overflow leading to a buffer
    overflow in nsScriptLoadHandler (bsc#1010404)

  - CVE-2016-5296: Heap-buffer-overflow WRITE in
    rasterize_edges_1 (bsc#1010395)

  - CVE-2016-9064: Addons update must verify IDs match
    between current and new versions (bsc#1010402)

  - CVE-2016-5290: Memory safety bugs fixed in Firefox 50
    and Firefox ESR 45.5 (bsc#1010427)

  - CVE-2016-5291: Same-origin policy violation using local
    HTML file and saved shortcut file (bsc#1010410) The
    following vulnerabilities were fixed in mozilla-nss
    3.21.3 :

  - CVE-2016-9074: Insufficient timing side-channel
    resistance in divSpoiler (bsc#1010422)

  - CVE-2016-5285: Missing NULL check in PK11_SignWithSymKey
    / ssl3_ComputeRecordMACConstantTime causes server crash
    (bsc#1010517) The following bugs were fixed :

  - Firefox would fail to go into fullscreen mode with some
    window managers (bsc#992549)

  - font warning messages would flood console, now using
    fontconfig configuration from firefox-fontconfig instead
    of the system one (bsc#1000751)

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
    value:"https://bugzilla.suse.com/1009026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010395"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010402"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012964"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/992549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5285.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5290.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5291.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5296.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5297.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9064.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9066.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9074.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9079.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20163105-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?702f52ca"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP2-LTSS:zypper in -t patch
slessp2-mfs2016-90-12883=1

SUSE Linux Enterprise Debuginfo 11-SP2:zypper in -t patch
dbgsp2-mfs2016-90-12883=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox nsSMILTimeContainer::NotifyTimeChange() RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/14");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"libfreebl3-32bit-3.21.3-30.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"mozilla-nss-32bit-3.21.3-30.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"libfreebl3-32bit-3.21.3-30.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"mozilla-nss-32bit-3.21.3-30.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"MozillaFirefox-45.5.1esr-63.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"MozillaFirefox-translations-45.5.1esr-63.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libfreebl3-3.21.3-30.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"mozilla-nss-3.21.3-30.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"mozilla-nss-devel-3.21.3-30.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"mozilla-nss-tools-3.21.3-30.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / mozilla-nss");
}
