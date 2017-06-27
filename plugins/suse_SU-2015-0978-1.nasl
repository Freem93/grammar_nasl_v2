#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0978-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83947);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/05/02 15:19:31 $");

  script_cve_id("CVE-2015-0797", "CVE-2015-2708", "CVE-2015-2709", "CVE-2015-2710", "CVE-2015-2713", "CVE-2015-2716");
  script_bugtraq_id(74181, 74611, 74615);
  script_osvdb_id(120789, 122020, 122021, 122022, 122023, 122033, 122036, 122039);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : MozillaFirefox (SUSE-SU-2015:0978-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to Firefox 31.7.0 ESR fixes the following issues :

MFSA 2015-46 (CVE-2015-2708, CVE-2015-2709): Miscellaneous memory
safety hazards (rv:38.0 / rv:31.7). Upstream references: bmo#1120655,
bmo#1143299, bmo#1151139, bmo#1152177, bmo#1111251, bmo#1117977,
bmo#1128064, bmo#1135066, bmo#1143194, bmo#1146101, bmo#1149526,
bmo#1153688, bmo#1155474.

MFSA 2015-47 (CVE-2015-0797): Buffer overflow parsing H.264 video with
Linux Gstreamer. Upstream references: bmo#1080995.

MFSA 2015-48 (CVE-2015-2710): Buffer overflow with SVG content and
CSS. Upstream references: bmo#1149542.

MFSA 2015-51 (CVE-2015-2713): Use-after-free during text processing
with vertical text enabled. Upstream references: bmo#1153478.

MFSA 2015-54 (CVE-2015-2716): Buffer overflow when parsing compressed
XML. Upstream references: bmo#1140537.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930622"
  );
  # https://download.suse.com/patch/finder/?keywords=ab9c724c1f8dad58c3aecf28fa855174
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?88c00acd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0797.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2708.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2709.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2710.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2713.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2716.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150978-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?63cd1e33"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11 SP3 :

zypper in -t patch sdksp3-firefox-20150510=10691

SUSE Linux Enterprise Server 11 SP3 for VMware :

zypper in -t patch slessp3-firefox-20150510=10691

SUSE Linux Enterprise Server 11 SP3 :

zypper in -t patch slessp3-firefox-20150510=10691

SUSE Linux Enterprise Desktop 11 SP3 :

zypper in -t patch sledsp3-firefox-20150510=10691

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/02");
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
if (! ereg(pattern:"^(SLED11|SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11 / SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", reference:"MozillaFirefox-31.7.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"MozillaFirefox-translations-31.7.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"MozillaFirefox-31.7.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"MozillaFirefox-translations-31.7.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"MozillaFirefox-31.7.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"MozillaFirefox-translations-31.7.0esr-0.8.1")) flag++;


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
