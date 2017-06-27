#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2061-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93288);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2016-2815", "CVE-2016-2818", "CVE-2016-2819", "CVE-2016-2821", "CVE-2016-2822", "CVE-2016-2824", "CVE-2016-2828", "CVE-2016-2830", "CVE-2016-2831", "CVE-2016-2834", "CVE-2016-2835", "CVE-2016-2836", "CVE-2016-2837", "CVE-2016-2838", "CVE-2016-2839", "CVE-2016-5252", "CVE-2016-5254", "CVE-2016-5258", "CVE-2016-5259", "CVE-2016-5262", "CVE-2016-5263", "CVE-2016-5264", "CVE-2016-5265", "CVE-2016-6354");
  script_osvdb_id(139436, 139437, 139438, 139439, 139440, 139441, 139442, 139443, 139444, 139445, 139446, 139447, 139448, 139449, 139450, 139451, 139452, 139453, 139454, 139455, 139456, 139457, 139458, 139461, 139463, 139466, 139467, 139468, 139469, 142032, 142419, 142420, 142421, 142422, 142423, 142424, 142425, 142426, 142427, 142428, 142429, 142430, 142431, 142432, 142433, 142434, 142435, 142468, 142474, 142476, 142478, 142479, 142480, 142481, 142482, 142483, 142484, 142485, 142486);

  script_name(english:"SUSE SLES11 Security Update : MozillaFirefox, MozillaFirefox-branding-SLED, mozilla-nspr / mozilla-nss (SUSE-SU-2016:2061-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaFirefox, MozillaFirefox-branding-SLE, mozilla-nspr and
mozilla-nss were updated to fix nine security issues. Mozilla Firefox
was updated to version 45.3.0 ESR. mozilla-nss was updated to version
3.21.1, mozilla-nspr to version 4.12. These security issues were fixed
in 45.3.0ESR :

  - CVE-2016-2835/CVE-2016-2836: Miscellaneous memory safety
    hazards (rv:48.0 / rv:45.3) (MFSA 2016-62)

  - CVE-2016-2830: Favicon network connection can persist
    when page is closed (MFSA 2016-63)

  - CVE-2016-2838: Buffer overflow rendering SVG with
    bidirectional content (MFSA 2016-64)

  - CVE-2016-2839: Cairo rendering crash due to memory
    allocation issue with FFmpeg 0.10 (MFSA 2016-65)

  - CVE-2016-5252: Stack underflow during 2D graphics
    rendering (MFSA 2016-67)

  - CVE-2016-5254: Use-after-free when using alt key and
    toplevel menus (MFSA 2016-70)

  - CVE-2016-5258: Use-after-free in DTLS during WebRTC
    session shutdown (MFSA 2016-72)

  - CVE-2016-5259: Use-after-free in service workers with
    nested sync events (MFSA 2016-73)

  - CVE-2016-5262: Scripts on marquee tag can execute in
    sandboxed iframes (MFSA 2016-76)

  - CVE-2016-2837: Buffer overflow in ClearKey Content
    Decryption Module (CDM) during video playback (MFSA
    2016-77)

  - CVE-2016-5263: Type confusion in display transformation
    (MFSA 2016-78)

  - CVE-2016-5264: Use-after-free when applying SVG effects
    (MFSA 2016-79)

  - CVE-2016-5265: Same-origin policy violation using local
    HTML file and saved shortcut file (MFSA 2016-80)

  - CVE-2016-6354: Fix for possible buffer overrun
    (bsc#990856) Security issues fixed in 45.2.0.ESR :

  - CVE-2016-2834: Memory safety bugs in NSS (MFSA 2016-61)
    (bsc#983639).

  - CVE-2016-2824: Out-of-bounds write with WebGL shader
    (MFSA 2016-53) (bsc#983651).

  - CVE-2016-2822: Addressbar spoofing though the SELECT
    element (MFSA 2016-52) (bsc#983652).

  - CVE-2016-2821: Use-after-free deleting tables from a
    contenteditable document (MFSA 2016-51) (bsc#983653).

  - CVE-2016-2819: Buffer overflow parsing HTML5 fragments
    (MFSA 2016-50) (bsc#983655).

  - CVE-2016-2828: Use-after-free when textures are used in
    WebGL operations after recycle pool destruction (MFSA
    2016-56) (bsc#983646).

  - CVE-2016-2831: Entering fullscreen and persistent
    pointerlock without user permission (MFSA 2016-58)
    (bsc#983643).

  - CVE-2016-2815, CVE-2016-2818: Miscellaneous memory
    safety hazards (MFSA 2016-49) (bsc#983638) These
    non-security issues were fixed :

  - Fix crashes on aarch64

  - Determine page size at runtime (bsc#984006)

  - Allow aarch64 to work in safe mode (bsc#985659)

  - Fix crashes on mainframes

  - Temporarily bind Firefox to the first CPU as a hotfix
    for an apparent race condition (bsc#989196, bsc#990628)
    All extensions must now be signed by addons.mozilla.org.
    Please read README.SUSE for more details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983653"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989196"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/990628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/990856"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2815.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2818.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2819.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2821.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2822.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2824.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2828.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2830.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2831.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2834.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2835.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2836.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2837.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2838.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2839.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5252.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5254.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5258.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5259.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5262.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5263.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5264.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5265.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6354.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162061-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b01d3fea"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP2-LTSS:zypper in -t patch
slessp2-MozillaFirefox-12690=1

SUSE Linux Enterprise Debuginfo 11-SP2:zypper in -t patch
dbgsp2-MozillaFirefox-12690=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:X/RC:R");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-branding-SLED");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox-fontconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"libfreebl3-32bit-3.21.1-26.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.12-25.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"mozilla-nss-32bit-3.21.1-26.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"libfreebl3-32bit-3.21.1-26.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"mozilla-nspr-32bit-4.12-25.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"mozilla-nss-32bit-3.21.1-26.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"MozillaFirefox-45.3.0esr-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"MozillaFirefox-branding-SLED-45.0-20.38")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"MozillaFirefox-translations-45.3.0esr-48.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"firefox-fontconfig-2.11.0-4.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libfreebl3-3.21.1-26.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"mozilla-nspr-4.12-25.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"mozilla-nspr-devel-4.12-25.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"mozilla-nss-3.21.1-26.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"mozilla-nss-devel-3.21.1-26.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"mozilla-nss-tools-3.21.1-26.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-branding-SLED / mozilla-nspr / mozilla-nss");
}
