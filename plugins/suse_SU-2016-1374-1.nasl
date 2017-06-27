#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1374-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(91298);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/27 20:24:08 $");

  script_cve_id("CVE-2016-2805", "CVE-2016-2807", "CVE-2016-2808", "CVE-2016-2814");
  script_osvdb_id(135562, 137609, 137612, 137613, 137614, 137615, 137616, 137639, 137642);

  script_name(english:"SUSE SLES11 Security Update : MozillaFirefox (SUSE-SU-2016:1374-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to MozillaFirefox 38.8.0 ESR fixes the following security
issues (bsc#977333) :

  - CVE-2016-2805: Miscellaneous memory safety hazards -
    MFSA 2016-39 (bsc#977374)

  - CVE-2016-2807: Miscellaneous memory safety hazards -
    MFSA 2016-39 (bsc#977376)

  - CVE-2016-2808: Write to invalid HashMap entry through
    JavaScript.watch()

  - MFSA 2016-47 (bsc#977386)

  - CVE-2016-2814: Buffer overflow in libstagefright with
    CENC offsets - MFSA 2016-44 (bsc#977381)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2805.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2807.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2808.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2814.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161374-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f72c9cc3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 5 :

zypper in -t patch sleclo50sp3-MozillaFirefox-12569=1

SUSE Manager Proxy 2.1 :

zypper in -t patch slemap21-MozillaFirefox-12569=1

SUSE Manager 2.1 :

zypper in -t patch sleman21-MozillaFirefox-12569=1

SUSE Linux Enterprise Software Development Kit 11-SP4 :

zypper in -t patch sdksp4-MozillaFirefox-12569=1

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-MozillaFirefox-12569=1

SUSE Linux Enterprise Server 11-SP3-LTSS :

zypper in -t patch slessp3-MozillaFirefox-12569=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-MozillaFirefox-12569=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-MozillaFirefox-12569=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/23");
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
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libfreebl3-32bit-3.20.2-30.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libsoftokn3-32bit-3.20.2-30.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.12-26.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"mozilla-nss-32bit-3.20.2-30.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libfreebl3-32bit-3.20.2-30.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libsoftokn3-32bit-3.20.2-30.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"mozilla-nspr-32bit-4.12-26.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"mozilla-nss-32bit-3.20.2-30.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"MozillaFirefox-38.8.0esr-40.5")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"MozillaFirefox-translations-38.8.0esr-40.5")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libfreebl3-3.20.2-30.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libsoftokn3-3.20.2-30.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mozilla-nspr-4.12-26.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mozilla-nss-3.20.2-30.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"mozilla-nss-tools-3.20.2-30.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libfreebl3-32bit-3.20.2-30.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libsoftokn3-32bit-3.20.2-30.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.12-26.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"mozilla-nss-32bit-3.20.2-30.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libfreebl3-32bit-3.20.2-30.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libsoftokn3-32bit-3.20.2-30.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"mozilla-nspr-32bit-4.12-26.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"mozilla-nss-32bit-3.20.2-30.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"MozillaFirefox-38.8.0esr-40.5")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"MozillaFirefox-translations-38.8.0esr-40.5")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libfreebl3-3.20.2-30.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libsoftokn3-3.20.2-30.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mozilla-nspr-4.12-26.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mozilla-nss-3.20.2-30.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"mozilla-nss-tools-3.20.2-30.1")) flag++;


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
