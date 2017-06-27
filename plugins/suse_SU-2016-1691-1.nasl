#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1691-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93166);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2016-2815", "CVE-2016-2818", "CVE-2016-2819", "CVE-2016-2821", "CVE-2016-2822", "CVE-2016-2824", "CVE-2016-2828", "CVE-2016-2831", "CVE-2016-2834");
  script_osvdb_id(139436, 139437, 139438, 139439, 139440, 139441, 139442, 139443, 139444, 139445, 139446, 139447, 139448, 139449, 139450, 139451, 139452, 139453, 139454, 139455, 139456, 139457, 139458, 139461, 139463, 139466, 139467, 139468, 139469);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : MozillaFirefox, MozillaFirefox-branding-SLE, mozilla-nspr, mozilla-nss (SUSE-SU-2016:1691-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaFirefox, MozillaFirefox-branding-SLE, mozilla-nss and
mozilla-nspr were updated to fix nine security issues.

Mozilla Firefox was updated to version 45.2.0 ESR. mozilla-nss was
updated to version 3.21.1.

These security issues were fixed :

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
    safety hazards (MFSA 2016-49) (bsc#983638)

These non-security issues were fixed :

  - bsc#982366: Unknown SSL protocol error in connections

  - Fix crashes on aarch64

  - Determine page size at runtime (bsc#984006)

  - Allow aarch64 to work in safe mode (bsc#985659)

  - Fix crashes on mainframes

All extensions must now be signed by addons.mozilla.org. Please read
README.SUSE for more details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982366"
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
    value:"https://bugzilla.suse.com/984126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985659"
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
    value:"https://www.suse.com/security/cve/CVE-2016-2831.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2834.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161691-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?18ef5c02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP1 :

zypper in -t patch SUSE-SLE-SDK-12-SP1-2016-1003=1

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2016-1003=1

SUSE Linux Enterprise Server 12-SP1 :

zypper in -t patch SUSE-SLE-SERVER-12-SP1-2016-1003=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2016-1003=1

SUSE Linux Enterprise Desktop 12-SP1 :

zypper in -t patch SUSE-SLE-DESKTOP-12-SP1-2016-1003=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2016-1003=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:X/RC:R");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-branding-SLE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoftokn3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoftokn3-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-certs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-certs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-sysinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");
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
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-45.2.0esr-75.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-branding-SLE-45.0-28.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-debuginfo-45.2.0esr-75.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-debugsource-45.2.0esr-75.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-translations-45.2.0esr-75.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libfreebl3-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libfreebl3-debuginfo-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libfreebl3-hmac-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsoftokn3-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsoftokn3-debuginfo-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsoftokn3-hmac-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nspr-4.12-15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nspr-debuginfo-4.12-15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nspr-debugsource-4.12-15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-certs-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-certs-debuginfo-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-debuginfo-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-debugsource-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-sysinit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-sysinit-debuginfo-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-tools-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-tools-debuginfo-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libfreebl3-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libfreebl3-debuginfo-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libfreebl3-hmac-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsoftokn3-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsoftokn3-debuginfo-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsoftokn3-hmac-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nspr-32bit-4.12-15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nspr-debuginfo-32bit-4.12-15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-certs-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-certs-debuginfo-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-debuginfo-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-sysinit-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-45.2.0esr-75.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-branding-SLE-45.0-28.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-debuginfo-45.2.0esr-75.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-debugsource-45.2.0esr-75.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-translations-45.2.0esr-75.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libfreebl3-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libfreebl3-debuginfo-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libfreebl3-hmac-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsoftokn3-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsoftokn3-debuginfo-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsoftokn3-hmac-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nspr-4.12-15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nspr-debuginfo-4.12-15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nspr-debugsource-4.12-15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-certs-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-certs-debuginfo-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-debuginfo-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-debugsource-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-sysinit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-sysinit-debuginfo-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-tools-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-tools-debuginfo-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libfreebl3-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libfreebl3-debuginfo-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libfreebl3-hmac-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsoftokn3-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsoftokn3-debuginfo-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsoftokn3-hmac-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nspr-32bit-4.12-15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nspr-debuginfo-32bit-4.12-15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-certs-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-certs-debuginfo-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-debuginfo-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-sysinit-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"MozillaFirefox-45.2.0esr-75.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"MozillaFirefox-branding-SLE-45.0-28.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"MozillaFirefox-debuginfo-45.2.0esr-75.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"MozillaFirefox-debugsource-45.2.0esr-75.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"MozillaFirefox-translations-45.2.0esr-75.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libfreebl3-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libfreebl3-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libfreebl3-debuginfo-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsoftokn3-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsoftokn3-debuginfo-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.12-15.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nspr-4.12-15.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.12-15.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-4.12-15.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nspr-debugsource-4.12-15.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-certs-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-debuginfo-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-debugsource-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-sysinit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-tools-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-tools-debuginfo-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"MozillaFirefox-45.2.0esr-75.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"MozillaFirefox-branding-SLE-45.0-28.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"MozillaFirefox-debuginfo-45.2.0esr-75.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"MozillaFirefox-debugsource-45.2.0esr-75.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"MozillaFirefox-translations-45.2.0esr-75.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libfreebl3-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libfreebl3-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libfreebl3-debuginfo-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsoftokn3-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsoftokn3-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsoftokn3-debuginfo-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.12-15.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mozilla-nspr-4.12-15.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.12-15.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-4.12-15.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mozilla-nspr-debugsource-4.12-15.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mozilla-nss-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mozilla-nss-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mozilla-nss-certs-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mozilla-nss-debuginfo-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mozilla-nss-debugsource-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mozilla-nss-sysinit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mozilla-nss-tools-3.21.1-46.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mozilla-nss-tools-debuginfo-3.21.1-46.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-branding-SLE / mozilla-nspr / mozilla-nss");
}
