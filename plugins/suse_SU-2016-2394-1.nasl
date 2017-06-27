#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2394-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93765);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/27 20:24:10 $");

  script_cve_id("CVE-2016-2177", "CVE-2016-2178", "CVE-2016-2179", "CVE-2016-2180", "CVE-2016-2181", "CVE-2016-2182", "CVE-2016-2183", "CVE-2016-6302", "CVE-2016-6303", "CVE-2016-6304", "CVE-2016-6306");
  script_osvdb_id(139313, 139471, 142095, 143021, 143259, 143309, 143387, 143388, 143389, 143392, 144687, 144688);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : openssl (SUSE-SU-2016:2394-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openssl fixes the following issues: OpenSSL Security
Advisory [22 Sep 2016] (bsc#999665) Severity: High

  - OCSP Status Request extension unbounded memory growth
    (CVE-2016-6304) (bsc#999666) Severity: Low

  - Pointer arithmetic undefined behaviour (CVE-2016-2177)
    (bsc#982575)

  - Constant time flag not preserved in DSA signing
    (CVE-2016-2178) (bsc#983249)

  - DTLS buffered message DoS (CVE-2016-2179) (bsc#994844)

  - OOB read in TS_OBJ_print_bio() (CVE-2016-2180)
    (bsc#990419)

  - DTLS replay protection DoS (CVE-2016-2181) (bsc#994749)

  - OOB write in BN_bn2dec() (CVE-2016-2182) (bsc#993819)

  - Birthday attack against 64-bit block ciphers (SWEET32)
    (CVE-2016-2183) (bsc#995359)

  - Malformed SHA512 ticket DoS (CVE-2016-6302) (bsc#995324)

  - OOB write in MDC2_Update() (CVE-2016-6303) (bsc#995377)

  - Certificate message OOB reads (CVE-2016-6306)
    (bsc#999668) More information can be found on:
    https://www.openssl.org/news/secadv/20160922.txt Also
    following bugs were fixed :

  - update expired S/MIME certs (bsc#979475)

  - improve s390x performance (bsc#982745)

  - allow >= 64GB AESGCM transfers (bsc#988591)

  - fix crash in print_notice (bsc#998190)

  - resume reading from /dev/urandom when interrupted by a
    signal (bsc#995075)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979475"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982575"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/988591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/990419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/993819"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/994749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/994844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/995075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/995324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/995359"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/995377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/998190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/999665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/999666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/999668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openssl.org/news/secadv/20160922.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2177.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2178.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2179.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2180.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2181.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2182.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2183.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6302.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6303.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6304.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6306.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162394-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?002d992f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2016-1393=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2016-1393=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2016-1393=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/28");
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
if (os_ver == "SLES12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"libopenssl1_0_0-1.0.1i-52.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libopenssl1_0_0-debuginfo-1.0.1i-52.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libopenssl1_0_0-hmac-1.0.1i-52.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openssl-1.0.1i-52.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openssl-debuginfo-1.0.1i-52.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openssl-debugsource-1.0.1i-52.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libopenssl1_0_0-32bit-1.0.1i-52.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.1i-52.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libopenssl1_0_0-hmac-32bit-1.0.1i-52.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libopenssl1_0_0-1.0.1i-52.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libopenssl1_0_0-32bit-1.0.1i-52.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-1.0.1i-52.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.1i-52.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"openssl-1.0.1i-52.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"openssl-debuginfo-1.0.1i-52.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"openssl-debugsource-1.0.1i-52.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl");
}
