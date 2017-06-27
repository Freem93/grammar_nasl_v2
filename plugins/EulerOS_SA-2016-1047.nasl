#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99810);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/04 13:21:27 $");

  script_cve_id(
    "CVE-2016-2177",
    "CVE-2016-2178",
    "CVE-2016-2179",
    "CVE-2016-2180",
    "CVE-2016-2181",
    "CVE-2016-2182",
    "CVE-2016-6302",
    "CVE-2016-6304",
    "CVE-2016-6306"
  );
  script_osvdb_id(
    139313,
    139471,
    142095,
    143021,
    143259,
    143309,
    143389,
    144687,
    144688
  );

  script_name(english:"EulerOS 2.0 SP1 : openssl (EulerOS-SA-2016-1047)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the openssl packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - OpenSSL through 1.0.2h incorrectly uses pointer
    arithmetic for heap-buffer boundary checks, which might
    allow remote attackers to cause a denial of service
    (integer overflow and application crash) or possibly
    have unspecified other impact by leveraging unexpected
    malloc behavior, related to s3_srvr.c, ssl_sess.c, and
    t1_lib.c.(CVE-2016-2177)

  - The dsa_sign_setup function in crypto/dsa/dsa_ossl.c in
    OpenSSL through 1.0.2h does not properly ensure the use
    of constant-time operations, which makes it easier for
    local users to discover a DSA private key via a timing
    side-channel attack.(CVE-2016-2178)

  - The DTLS implementation in OpenSSL before 1.1.0 does
    not properly restrict the lifetime of queue entries
    associated with unused out-of-order messages, which
    allows remote attackers to cause a denial of service
    (memory consumption) by maintaining many crafted DTLS
    sessions simultaneously, related to d1_lib.c,
    statem_dtls.c, statem_lib.c, and
    statem_srvr.c.(CVE-2016-2179)

  - The TS_OBJ_print_bio function in crypto/ts/ts_lib.c in
    the X.509 Public Key Infrastructure Time-Stamp Protocol
    (TSP) implementation in OpenSSL through 1.0.2h allows
    remote attackers to cause a denial of service
    (out-of-bounds read and application crash) via a
    crafted time-stamp file that is mishandled by the
    'openssl ts' command.(CVE-2016-2180)

  - The Anti-Replay feature in the DTLS implementation in
    OpenSSL before 1.1.0 mishandles early use of a new
    epoch number in conjunction with a large sequence
    number, which allows remote attackers to cause a denial
    of service (false-positive packet drops) via spoofed
    DTLS records, related to rec_layer_d1.c and
    ssl3_record.c.(CVE-2016-2181)

  - The BN_bn2dec function in crypto/bn/bn_print.c in
    OpenSSL before 1.1.0 does not properly validate
    division results, which allows remote attackers to
    cause a denial of service (out-of-bounds write and
    application crash) or possibly have unspecified other
    impact via unknown vectors.(CVE-2016-2182)

  - The tls_decrypt_ticket function in ssl/t1_lib.c in
    OpenSSL before 1.1.0 does not consider the HMAC size
    during validation of the ticket length, which allows
    remote attackers to cause a denial of service via a
    ticket that is too short.(CVE-2016-6302)

  - Multiple memory leaks in t1_lib.c in OpenSSL before
    1.0.1u, 1.0.2 before 1.0.2i, and 1.1.0 before 1.1.0a
    allow remote attackers to cause a denial of service
    (memory consumption) via large OCSP Status Request
    extensions.(CVE-2016-6304)

  - The certificate parser in OpenSSL before 1.0.1u and
    1.0.2 before 1.0.2i might allow remote attackers to
    cause a denial of service (out-of-bounds read) via
    crafted certificate operations, related to s3_clnt.c
    and s3_srvr.c.(CVE-2016-6306)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1047
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cfeab5a");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(1)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1");

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

flag = 0;

pkgs = ["openssl-1.0.1e-51.7",
        "openssl-devel-1.0.1e-51.7",
        "openssl-libs-1.0.1e-51.7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl");
}
