#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1269-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(84899);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/05/11 13:40:22 $");

  script_cve_id("CVE-2015-2721", "CVE-2015-2722", "CVE-2015-2724", "CVE-2015-2725", "CVE-2015-2726", "CVE-2015-2728", "CVE-2015-2730", "CVE-2015-2733", "CVE-2015-2734", "CVE-2015-2735", "CVE-2015-2736", "CVE-2015-2737", "CVE-2015-2738", "CVE-2015-2739", "CVE-2015-2740", "CVE-2015-2743", "CVE-2015-4000");
  script_bugtraq_id(74733, 75541);
  script_osvdb_id(122331, 124070, 124071, 124072, 124073, 124074, 124075, 124076, 124077, 124078, 124079, 124080, 124081, 124082, 124083, 124084, 124085, 124086, 124087, 124089, 124092, 124093, 124094, 124095, 124096, 124097, 124098, 124099, 124100, 124101, 124104, 124105);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : MozillaFirefox, mozilla-nspr, mozilla-nss (SUSE-SU-2015:1269-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaFirefox, mozilla-nspr, and mozilla-nss were updated to fix 17
security issues.

For more details please check the changelogs.

  - CVE-2015-2724/CVE-2015-2725/CVE-2015-2726: Miscellaneous
    memory safety hazards (bsc#935979).

  - CVE-2015-2728: Type confusion in Indexed Database
    Manager (bsc#935979).

  - CVE-2015-2730: ECDSA signature validation fails to
    handle some signatures correctly (bsc#935979).

  - CVE-2015-2722/CVE-2015-2733: Use-after-free in workers
    while using XMLHttpRequest (bsc#935979).

  - CVE-2015-2734/CVE-2015-2735/CVE-2015-2736/CVE-2015-2737/
    CVE-2015-2738/CVE-2 015-2739/CVE-2015-2740:
    Vulnerabilities found through code inspection
    (bsc#935979).

  - CVE-2015-2743: Privilege escalation in PDF.js
    (bsc#935979).

  - CVE-2015-4000: NSS accepts export-length DHE keys with
    regular DHE cipher suites (bsc#935033).

  - CVE-2015-2721: NSS incorrectly permits skipping of
    ServerKeyExchange (bsc#935979).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/856315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935033"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2721.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2722.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2724.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2725.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2726.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2728.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2730.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2733.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2734.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2735.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2736.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2737.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2738.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2739.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2740.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2743.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4000.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151269-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?03992c1e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively, you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-330=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-330=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-330=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/21");
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
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

rpm_list =get_kb_item("Host/SuSE/rpm-list");
if (!rpm_list) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

rpm_fixed = ereg_replace(string:rpm_list, pattern:"_CKBI_1\.98-", replace:"-");

flag = 0;
if (rpm_check(release:"SLES12", reference:"MozillaFirefox-31.8.0esr-37.3", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"MozillaFirefox-debuginfo-31.8.0esr-37.3", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"MozillaFirefox-debugsource-31.8.0esr-37.3", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"MozillaFirefox-devel-31.8.0esr-37.3", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"MozillaFirefox-translations-31.8.0esr-37.3", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"libfreebl3-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"libfreebl3-debuginfo-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"libfreebl3-hmac-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"libsoftokn3-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"libsoftokn3-debuginfo-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"libsoftokn3-hmac-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"mozilla-nspr-4.10.8-3.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"mozilla-nspr-debuginfo-4.10.8-3.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"mozilla-nspr-debugsource-4.10.8-3.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"mozilla-nspr-devel-4.10.8-3.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"mozilla-nss-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"mozilla-nss-certs-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"mozilla-nss-certs-debuginfo-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"mozilla-nss-debuginfo-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"mozilla-nss-debugsource-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"mozilla-nss-devel-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"mozilla-nss-tools-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"mozilla-nss-tools-debuginfo-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"libfreebl3-32bit-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"libfreebl3-debuginfo-32bit-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"libfreebl3-hmac-32bit-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"libsoftokn3-32bit-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"libsoftokn3-debuginfo-32bit-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"libsoftokn3-hmac-32bit-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"mozilla-nspr-32bit-4.10.8-3.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"mozilla-nspr-debuginfo-32bit-4.10.8-3.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"mozilla-nss-32bit-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"mozilla-nss-certs-32bit-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"mozilla-nss-certs-debuginfo-32bit-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLES12", reference:"mozilla-nss-debuginfo-32bit-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"MozillaFirefox-31.8.0esr-37.3", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"MozillaFirefox-debuginfo-31.8.0esr-37.3", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"MozillaFirefox-debugsource-31.8.0esr-37.3", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"MozillaFirefox-devel-31.8.0esr-37.3", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"MozillaFirefox-translations-31.8.0esr-37.3", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"libfreebl3-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"libfreebl3-32bit-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"libfreebl3-debuginfo-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"libsoftokn3-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"libsoftokn3-32bit-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"libsoftokn3-debuginfo-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.8-3.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"mozilla-nspr-4.10.8-3.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.10.8-3.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-4.10.8-3.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"mozilla-nspr-debugsource-4.10.8-3.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"mozilla-nspr-devel-4.10.8-3.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"mozilla-nss-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"mozilla-nss-32bit-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"mozilla-nss-certs-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"mozilla-nss-debuginfo-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"mozilla-nss-debugsource-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"mozilla-nss-devel-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"mozilla-nss-tools-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;
if (rpm_check(release:"SLED12", cpu:"x86_64", reference:"mozilla-nss-tools-debuginfo-3.19.2-21.1", rpm_list:rpm_fixed)) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / mozilla-nspr / mozilla-nss");
}
