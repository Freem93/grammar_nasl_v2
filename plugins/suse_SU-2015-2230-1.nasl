#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:2230-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(87280);
  script_version("$Revision: 2.11 $");
  script_cvs_date("$Date: 2016/12/27 20:14:33 $");

  script_cve_id("CVE-2015-3194", "CVE-2015-3195", "CVE-2015-3196");
  script_osvdb_id(131038, 131039, 131040);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : openssl (SUSE-SU-2015:2230-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openssl fixes the following issues :

Security fixes :

  - CVE-2015-3194: The signature verification routines will
    crash with a NULL pointer dereference if presented with
    an ASN.1 signature using the RSA PSS algorithm and
    absent mask generation function parameter. Since these
    routines are used to verify certificate signature
    algorithms this can be used to crash any certificate
    verification operation and exploited in a DoS attack.
    Any application which performs certificate verification
    is vulnerable including OpenSSL clients and servers
    which enable client authentication. (bsc#957815)

  - CVE-2015-3195: When presented with a malformed
    X509_ATTRIBUTE structure OpenSSL would leak memory. This
    structure is used by the PKCS#7 and CMS routines so any
    application which reads PKCS#7 or CMS data from
    untrusted sources is affected. SSL/TLS is not affected.
    (bsc#957812)

  - CVE-2015-3196: If PSK identity hints are received by a
    multi-threaded client then the values were wrongly
    updated in the parent SSL_CTX structure. This could
    result in a race condition potentially leading to a
    double free of the identify hint data. (bsc#957813)

Non security bugs fixed :

  - Improve S/390 performance on IBM z196 and z13
    (bsc#954256)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3194.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3195.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3196.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20152230-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76634ad7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP1 :

zypper in -t patch SUSE-SLE-SDK-12-SP1-2015-954=1

SUSE Linux Enterprise Server 12-SP1 :

zypper in -t patch SUSE-SLE-SERVER-12-SP1-2015-954=1

SUSE Linux Enterprise Desktop 12-SP1 :

zypper in -t patch SUSE-SLE-DESKTOP-12-SP1-2015-954=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/09");
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

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"libopenssl1_0_0-1.0.1i-36.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libopenssl1_0_0-debuginfo-1.0.1i-36.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libopenssl1_0_0-hmac-1.0.1i-36.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openssl-1.0.1i-36.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openssl-debuginfo-1.0.1i-36.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openssl-debugsource-1.0.1i-36.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libopenssl1_0_0-32bit-1.0.1i-36.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.1i-36.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libopenssl1_0_0-hmac-32bit-1.0.1i-36.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libopenssl1_0_0-1.0.1i-36.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libopenssl1_0_0-32bit-1.0.1i-36.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-1.0.1i-36.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.1i-36.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"openssl-1.0.1i-36.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"openssl-debuginfo-1.0.1i-36.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"openssl-debugsource-1.0.1i-36.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl");
}
