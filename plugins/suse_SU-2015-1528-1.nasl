#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1528-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(85906);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2015/11/30 15:53:21 $");

  script_cve_id("CVE-2015-4473", "CVE-2015-4474", "CVE-2015-4475", "CVE-2015-4478", "CVE-2015-4479", "CVE-2015-4484", "CVE-2015-4485", "CVE-2015-4486", "CVE-2015-4487", "CVE-2015-4488", "CVE-2015-4489", "CVE-2015-4491", "CVE-2015-4492", "CVE-2015-4495");
  script_osvdb_id(125839, 126004, 126005, 126006, 126007, 126008, 126009, 126010, 126011, 126012, 126013, 126015, 126016, 126021, 126022, 126023, 126024, 126025, 126026, 126027, 126028);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : MozillaFirefox, mozilla-nss (SUSE-SU-2015:1528-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox is being updated to the current Firefox 38ESR branch
(specifically the 38.2.0ESR release).

Security issues fixed :

  - MFSA 2015-78 / CVE-2015-4495: Same origin violation and
    local file stealing via PDF reader

  - MFSA 2015-79 / CVE-2015-4473/CVE-2015-4474:
    Miscellaneous memory safety hazards (rv:40.0 / rv:38.2)

  - MFSA 2015-80 / CVE-2015-4475: Out-of-bounds read with
    malformed MP3 file

  - MFSA 2015-82 / CVE-2015-4478: Redefinition of
    non-configurable JavaScript object properties

  - MFSA 2015-83 / CVE-2015-4479: Overflow issues in
    libstagefright

  - MFSA 2015-87 / CVE-2015-4484: Crash when using shared
    memory in JavaScript

  - MFSA 2015-88 / CVE-2015-4491: Heap overflow in
    gdk-pixbuf when scaling bitmap images

  - MFSA 2015-89 / CVE-2015-4485/CVE-2015-4486: Buffer
    overflows on Libvpx when decoding WebM video

  - MFSA 2015-90 /
    CVE-2015-4487/CVE-2015-4488/CVE-2015-4489:
    Vulnerabilities found through code inspection

  - MFSA 2015-92 / CVE-2015-4492: Use-after-free in
    XMLHttpRequest with shared workers

This update also contains a lot of feature improvements and bug fixes
from 31ESR to 38ESR.

Also the Mozilla NSS library switched its CKBI API from 1.98 to 2.4,
which is what Firefox 38ESR uses.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4473.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4474.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4475.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4478.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4479.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4484.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4485.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4486.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4487.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4488.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4489.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4491.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4492.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4495.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151528-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d87736ce"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4 :

zypper in -t patch sdksp4-firefox38-20150820-12083=1

SUSE Linux Enterprise Software Development Kit 11-SP3 :

zypper in -t patch sdksp3-firefox38-20150820-12083=1

SUSE Linux Enterprise Server for VMWare 11-SP3 :

zypper in -t patch slessp3-firefox38-20150820-12083=1

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-firefox38-20150820-12083=1

SUSE Linux Enterprise Server 11-SP3 :

zypper in -t patch slessp3-firefox38-20150820-12083=1

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-firefox38-20150820-12083=1

SUSE Linux Enterprise Desktop 11-SP3 :

zypper in -t patch sledsp3-firefox38-20150820-12083=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-firefox38-20150820-12083=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-firefox38-20150820-12083=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-branding-SLED");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/11");
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
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libfreebl3-32bit-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libsoftokn3-32bit-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"mozilla-nss-32bit-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libfreebl3-32bit-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libsoftokn3-32bit-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"mozilla-nss-32bit-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"MozillaFirefox-38.2.1esr-19.3")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"MozillaFirefox-branding-SLED-31.0-0.12.51")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"MozillaFirefox-translations-38.2.1esr-19.3")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libfreebl3-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libsoftokn3-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mozilla-nss-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mozilla-nss-tools-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libfreebl3-32bit-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libsoftokn3-32bit-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"mozilla-nss-32bit-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libfreebl3-32bit-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libsoftokn3-32bit-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"mozilla-nss-32bit-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"MozillaFirefox-38.2.1esr-19.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"MozillaFirefox-branding-SLED-31.0-0.12.51")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"MozillaFirefox-translations-38.2.1esr-19.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libfreebl3-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libsoftokn3-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mozilla-nss-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mozilla-nss-tools-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"MozillaFirefox-38.2.1esr-19.3")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"MozillaFirefox-branding-SLED-31.0-0.12.51")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"MozillaFirefox-translations-38.2.1esr-19.3")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libfreebl3-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libsoftokn3-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mozilla-nss-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mozilla-nss-tools-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libfreebl3-32bit-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libsoftokn3-32bit-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"mozilla-nss-32bit-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"MozillaFirefox-38.2.1esr-19.3")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"MozillaFirefox-branding-SLED-31.0-0.12.51")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"MozillaFirefox-translations-38.2.1esr-19.3")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libfreebl3-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libsoftokn3-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"mozilla-nss-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"mozilla-nss-tools-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"MozillaFirefox-38.2.1esr-19.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"MozillaFirefox-branding-SLED-31.0-0.12.51")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"MozillaFirefox-translations-38.2.1esr-19.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libfreebl3-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libsoftokn3-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"mozilla-nss-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"mozilla-nss-tools-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libfreebl3-32bit-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libsoftokn3-32bit-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"mozilla-nss-32bit-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"MozillaFirefox-38.2.1esr-19.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"MozillaFirefox-branding-SLED-31.0-0.12.51")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"MozillaFirefox-translations-38.2.1esr-19.3")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"libfreebl3-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"libsoftokn3-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"mozilla-nss-3.19.2.0-0.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"mozilla-nss-tools-3.19.2.0-0.16.1")) flag++;


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
