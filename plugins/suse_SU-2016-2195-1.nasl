#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2195-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93313);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2016-2830", "CVE-2016-2835", "CVE-2016-2836", "CVE-2016-2837", "CVE-2016-2838", "CVE-2016-2839", "CVE-2016-5252", "CVE-2016-5254", "CVE-2016-5258", "CVE-2016-5259", "CVE-2016-5262", "CVE-2016-5263", "CVE-2016-5264", "CVE-2016-5265", "CVE-2016-6354");
  script_osvdb_id(142032, 142419, 142420, 142421, 142422, 142423, 142424, 142425, 142426, 142427, 142428, 142429, 142430, 142431, 142432, 142433, 142434, 142435, 142468, 142474, 142476, 142478, 142479, 142480, 142481, 142482, 142483, 142484, 142485, 142486);

  script_name(english:"SUSE SLES11 Security Update : MozillaFirefox (SUSE-SU-2016:2195-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to 45.3.0 ESR to fix the following issues
(bsc#991809) :

  - MFSA 2016-62/CVE-2016-2835/CVE-2016-2836 Miscellaneous
    memory safety hazards (rv:48.0 / rv:45.3)

  - MFSA 2016-63/CVE-2016-2830 Favicon network connection
    can persist when page is closed

  - MFSA 2016-64/CVE-2016-2838 Buffer overflow rendering SVG
    with bidirectional content

  - MFSA 2016-65/CVE-2016-2839 Cairo rendering crash due to
    memory allocation issue with FFmpeg 0.10

  - MFSA 2016-67/CVE-2016-5252 Stack underflow during 2D
    graphics rendering

  - MFSA 2016-70/CVE-2016-5254 Use-after-free when using alt
    key and toplevel menus

  - MFSA 2016-72/CVE-2016-5258 Use-after-free in DTLS during
    WebRTC session shutdown

  - MFSA 2016-73/CVE-2016-5259 Use-after-free in service
    workers with nested sync events

  - MFSA 2016-76/CVE-2016-5262 Scripts on marquee tag can
    execute in sandboxed iframes

  - MFSA 2016-77/CVE-2016-2837 Buffer overflow in ClearKey
    Content Decryption Module (CDM) during video playback

  - MFSA 2016-78/CVE-2016-5263 Type confusion in display
    transformation

  - MFSA 2016-79/CVE-2016-5264 Use-after-free when applying
    SVG effects

  - MFSA 2016-80/CVE-2016-5265 Same-origin policy violation
    using local HTML file and saved shortcut file

  - CVE-2016-6354: Fix for possible buffer overrun
    (bsc#990856) Also a temporary workaround was added :

  - Temporarily bind Firefox to the first CPU as a hotfix
    for an apparent race condition (bsc#989196, bsc#990628)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
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
    value:"https://www.suse.com/security/cve/CVE-2016-2830.html"
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
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162195-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24d378a5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 5:zypper in -t patch
sleclo50sp3-MozillaFirefox-12722=1

SUSE Manager Proxy 2.1:zypper in -t patch
slemap21-MozillaFirefox-12722=1

SUSE Manager 2.1:zypper in -t patch sleman21-MozillaFirefox-12722=1

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-MozillaFirefox-12722=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-MozillaFirefox-12722=1

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-MozillaFirefox-12722=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-MozillaFirefox-12722=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-MozillaFirefox-12722=1

SUSE Linux Enterprise Debuginfo 11-SP3:zypper in -t patch
dbgsp3-MozillaFirefox-12722=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/30");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"MozillaFirefox-45.3.0esr-50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"MozillaFirefox-translations-45.3.0esr-50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"MozillaFirefox-45.3.0esr-50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"MozillaFirefox-translations-45.3.0esr-50.1")) flag++;


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
