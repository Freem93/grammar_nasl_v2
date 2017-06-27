#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2458-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93893);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:10 $");

  script_cve_id("CVE-2016-2177", "CVE-2016-2178", "CVE-2016-2179", "CVE-2016-2181", "CVE-2016-2182", "CVE-2016-2183", "CVE-2016-6302", "CVE-2016-6303", "CVE-2016-6304", "CVE-2016-6306");
  script_osvdb_id(139313, 139471, 143021, 143259, 143309, 143387, 143388, 143389, 143392, 144687, 144688);

  script_name(english:"SUSE SLES11 Security Update : openssl (SUSE-SU-2016:2458-1)");
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

  - Pointer arithmetic undefined behavior (CVE-2016-2177)
    (bsc#982575)

  - Constant time flag not preserved in DSA signing
    (CVE-2016-2178) (bsc#983249)

  - DTLS buffered message DoS (CVE-2016-2179) (bsc#994844)

  - DTLS replay protection DoS (CVE-2016-2181) (bsc#994749)

  - OOB write in BN_bn2dec() (CVE-2016-2182) (bsc#993819)

  - Birthday attack against 64-bit block ciphers (SWEET32)
    (CVE-2016-2183) (bsc#995359)

  - Malformed SHA512 ticket DoS (CVE-2016-6302) (bsc#995324)

  - OOB write in MDC2_Update() (CVE-2016-6303) (bsc#995377)

  - Certificate message OOB reads (CVE-2016-6306)
    (bsc#999668) More information can be found on:
    https://www.openssl.org/news/secadv/20160922.txt Bugs
    fixed :

  - Update expired S/MIME certs (bsc#979475)

  - Fix crash in print_notice (bsc#998190)

  - Resume reading from /dev/urandom when interrupted by a
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
    value:"https://bugzilla.suse.com/983249"
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
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162458-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?20e4ec5d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Studio Onsite 1.3:zypper in -t patch slestso13-openssl-12774=1

SUSE OpenStack Cloud 5:zypper in -t patch sleclo50sp3-openssl-12774=1

SUSE Manager Proxy 2.1:zypper in -t patch slemap21-openssl-12774=1

SUSE Manager 2.1:zypper in -t patch sleman21-openssl-12774=1

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-openssl-12774=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-openssl-12774=1

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-openssl-12774=1

SUSE Linux Enterprise Server 11-SP2-LTSS:zypper in -t patch
slessp2-openssl-12774=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-openssl-12774=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-openssl-12774=1

SUSE Linux Enterprise Debuginfo 11-SP3:zypper in -t patch
dbgsp3-openssl-12774=1

SUSE Linux Enterprise Debuginfo 11-SP2:zypper in -t patch
dbgsp2-openssl-12774=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl0_9_8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl0_9_8-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/06");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^(2|3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2/3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libopenssl0_9_8-32bit-0.9.8j-0.102.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libopenssl0_9_8-hmac-32bit-0.9.8j-0.102.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libopenssl0_9_8-32bit-0.9.8j-0.102.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libopenssl0_9_8-hmac-32bit-0.9.8j-0.102.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libopenssl0_9_8-0.9.8j-0.102.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libopenssl0_9_8-hmac-0.9.8j-0.102.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"openssl-0.9.8j-0.102.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"openssl-doc-0.9.8j-0.102.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libopenssl0_9_8-32bit-0.9.8j-0.102.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libopenssl0_9_8-hmac-32bit-0.9.8j-0.102.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libopenssl0_9_8-32bit-0.9.8j-0.102.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libopenssl0_9_8-hmac-32bit-0.9.8j-0.102.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libopenssl-devel-0.9.8j-0.102.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libopenssl0_9_8-0.9.8j-0.102.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libopenssl0_9_8-hmac-0.9.8j-0.102.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"openssl-0.9.8j-0.102.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"openssl-doc-0.9.8j-0.102.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"libopenssl0_9_8-32bit-0.9.8j-0.102.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"libopenssl0_9_8-hmac-32bit-0.9.8j-0.102.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"libopenssl0_9_8-32bit-0.9.8j-0.102.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"libopenssl0_9_8-hmac-32bit-0.9.8j-0.102.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libopenssl-devel-0.9.8j-0.102.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libopenssl0_9_8-0.9.8j-0.102.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libopenssl0_9_8-hmac-0.9.8j-0.102.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"openssl-0.9.8j-0.102.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"openssl-doc-0.9.8j-0.102.2")) flag++;


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
