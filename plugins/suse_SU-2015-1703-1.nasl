#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1703-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(86341);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2015/11/08 16:01:24 $");

  script_cve_id("CVE-2015-4500", "CVE-2015-4501", "CVE-2015-4506", "CVE-2015-4509", "CVE-2015-4511", "CVE-2015-4517", "CVE-2015-4519", "CVE-2015-4520", "CVE-2015-4521", "CVE-2015-4522", "CVE-2015-7174", "CVE-2015-7175", "CVE-2015-7176", "CVE-2015-7177", "CVE-2015-7180");
  script_osvdb_id(127875, 127876, 127877, 127878, 127879, 127880, 127881, 127882, 127883, 127884, 127890, 127892, 127899, 127915, 127916, 127917, 127918, 127919, 127920, 127921, 127922, 127923, 127924);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : MozillaFirefox (SUSE-SU-2015:1703-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to version 38.3.0 ESR (bsc#947003), fixing
bugs and security issues.

  - MFSA 2015-96/CVE-2015-4500/CVE-2015-4501 Miscellaneous
    memory safety hazards (rv:41.0 / rv:38.3)

  - MFSA 2015-101/CVE-2015-4506 Buffer overflow in libvpx
    while parsing vp9 format video

  - MFSA 2015-105/CVE-2015-4511 Buffer overflow while
    decoding WebM video

  - MFSA 2015-106/CVE-2015-4509 Use-after-free while
    manipulating HTML media content

  - MFSA 2015-110/CVE-2015-4519 Dragging and dropping images
    exposes final URL after redirects

  - MFSA 2015-111/CVE-2015-4520 Errors in the handling of
    CORS preflight request headers

  - MFSA 2015-112/CVE-2015-4517/CVE-2015-4521/CVE-2015-4522
    CVE-2015-7174/CVE-2015-7175/CVE-2015-7176/CVE-2015-7177
    CVE-2015-7180 Vulnerabilities found through code
    inspection

More details can be found on
https://www.mozilla.org/en-US/security/advisories/

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/947003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4500.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4501.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4506.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4509.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4511.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4517.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4519.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4520.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4521.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4522.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7174.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7175.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7176.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7177.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7180.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151703-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9815d848"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4 :

zypper in -t patch sdksp4-firefox-20150923-12122=1

SUSE Linux Enterprise Software Development Kit 11-SP3 :

zypper in -t patch sdksp3-firefox-20150923-12122=1

SUSE Linux Enterprise Server for VMWare 11-SP3 :

zypper in -t patch slessp3-firefox-20150923-12122=1

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-firefox-20150923-12122=1

SUSE Linux Enterprise Server 11-SP3 :

zypper in -t patch slessp3-firefox-20150923-12122=1

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-firefox-20150923-12122=1

SUSE Linux Enterprise Desktop 11-SP3 :

zypper in -t patch sledsp3-firefox-20150923-12122=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-firefox-20150923-12122=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-firefox-20150923-12122=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(SLED11|SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11 / SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! ereg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"MozillaFirefox-38.3.0esr-22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"MozillaFirefox-translations-38.3.0esr-22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"MozillaFirefox-38.3.0esr-22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"MozillaFirefox-translations-38.3.0esr-22.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"MozillaFirefox-38.3.0esr-22.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"MozillaFirefox-translations-38.3.0esr-22.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"MozillaFirefox-38.3.0esr-22.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"MozillaFirefox-translations-38.3.0esr-22.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"MozillaFirefox-38.3.0esr-22.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"MozillaFirefox-translations-38.3.0esr-22.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"MozillaFirefox-38.3.0esr-22.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"MozillaFirefox-translations-38.3.0esr-22.1")) flag++;


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
