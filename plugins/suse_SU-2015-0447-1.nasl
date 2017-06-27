#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0447-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83692);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/05/11 13:40:21 $");

  script_cve_id("CVE-2015-0822", "CVE-2015-0827", "CVE-2015-0831", "CVE-2015-0835", "CVE-2015-0836");
  script_bugtraq_id(72742, 72746, 72748, 72755, 72756);
  script_osvdb_id(118696, 118699, 118704, 118707, 118710, 118711, 118712, 118717, 118718, 118719, 118720, 118721, 118722);

  script_name(english:"SUSE SLES10 / SLES11 Security Update : Mozilla Firefox (SUSE-SU-2015:0447-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox has been updated to version 31.5.0 ESR to fix five
security issues.

These security issues have been fixed :

  - CVE-2015-0836: Multiple unspecified vulnerabilities in
    the browser engine in Mozilla Firefox before 31.5
    allowed remote attackers to cause a denial of service
    (memory corruption and application crash) or possibly
    execute arbitrary code via unknown vectors (bnc#917597).

  - CVE-2015-0827: Heap-based buffer overflow in the
    mozilla::gfx::CopyRect function in Mozilla Firefox
    before 31.5 allowed remote attackers to obtain sensitive
    information from uninitialized process memory via a
    malformed SVG graphic (bnc#917597).

  - CVE-2015-0835: Multiple unspecified vulnerabilities in
    the browser engine in Mozilla Firefox before 36.0
    allowed remote attackers to cause a denial of service
    (memory corruption and application crash) or possibly
    execute arbitrary code via unknown vectors (bnc#917597).

  - CVE-2015-0831: Use-after-free vulnerability in the
    mozilla::dom::IndexedDB::IDBObjectStore::CreateIndex
    function in Mozilla Firefox before 31.5 allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (heap memory corruption) via crafted content
    that is improperly handled during IndexedDB index
    creation (bnc#917597).

  - CVE-2015-0822: The Form Autocompletion feature in
    Mozilla Firefox before 31.5 allowed remote attackers to
    read arbitrary files via crafted JavaScript code
    (bnc#917597).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=05f52c1e0f407db47eeda7f443c74a59
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ba690b92"
  );
  # http://download.suse.com/patch/finder/?keywords=620f31f396ab13eab1f112060f474aba
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f6f122ec"
  );
  # http://download.suse.com/patch/finder/?keywords=a337580683ba9ef729d391b0364a996a
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e14fd7d0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0822.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0827.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0831.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0836.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/917597"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150447-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?36576be6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11 SP2 LTSS :

zypper in -t patch slessp2-MozillaFirefox=10377

SUSE Linux Enterprise Server 11 SP1 LTSS :

zypper in -t patch slessp1-MozillaFirefox=10368

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(SLES10|SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES10 / SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP1/2", os_ver + " SP" + sp);
if (os_ver == "SLES10" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"1", reference:"MozillaFirefox-31.5.0esr-0.4.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"MozillaFirefox-translations-31.5.0esr-0.4.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"MozillaFirefox-31.5.0esr-0.4.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"MozillaFirefox-translations-31.5.0esr-0.4.2.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"MozillaFirefox-31.5.0esr-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"MozillaFirefox-translations-31.5.0esr-0.5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Firefox");
}
