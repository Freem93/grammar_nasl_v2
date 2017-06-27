#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95255);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/11/23 20:31:31 $");

  script_cve_id(
    "CVE-2016-2177",
    "CVE-2016-2178",
    "CVE-2016-2179",
    "CVE-2016-2180",
    "CVE-2016-2181",
    "CVE-2016-2182",
    "CVE-2016-2183",
    "CVE-2016-6302",
    "CVE-2016-6303",
    "CVE-2016-6304",
    "CVE-2016-6306",
    "CVE-2016-7052"
  );
  script_bugtraq_id(
    91081,
    91319,
    92117,
    92557,
    92628,
    92630,
    92982,
    92984,
    92987,
    93150,
    93153,
    93171
  );
  script_osvdb_id(
    139313,
    139471,
    142095,
    143021,
    143259,
    143309,
    143387,
    143388,
    143389,
    143392,
    144687,
    144688,
    144804
  );

  script_name(english:"AIX OpenSSL Advisory : openssl_advisory21.asc (SWEET32)");
  script_summary(english:"Checks the version of the OpenSSL packages and iFixes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of OpenSSL installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote AIX host is affected by
the following vulnerabilities :

  - Multiple integer overflow conditions exist in s3_srvr.c,
    ssl_sess.c, and t1_lib.c due to improper use of pointer
    arithmetic for heap-buffer boundary checks. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service. (CVE-2016-2177)

  - An information disclosure vulnerability exists in the
    dsa_sign_setup() function in dsa_ossl.c due to a failure
    to properly ensure the use of constant-time operations.
    An unauthenticated, remote attacker can exploit this,
    via a timing side-channel attack, to disclose DSA key
    information. (CVE-2016-2178)

  - A denial of service vulnerability exists in the DTLS
    implementation due to a failure to properly restrict the
    lifetime of queue entries associated with unused
    out-of-order messages. An unauthenticated, remote
    attacker can exploit this, by maintaining multiple
    crafted DTLS sessions simultaneously, to exhaust memory.
    (CVE-2016-2179)

  - An out-of-bounds read error exists in the X.509 Public
    Key Infrastructure Time-Stamp Protocol (TSP)
    implementation. An unauthenticated, remote attacker can
    exploit this, via a crafted time-stamp file that is
    mishandled by the 'openssl ts' command, to cause 
    denial of service or to disclose sensitive information.
    (CVE-2016-2180)

  - A denial of service vulnerability exists in the
    Anti-Replay feature in the DTLS implementation due to
    improper handling of epoch sequence numbers in records.
    An unauthenticated, remote attacker can exploit this,
    via spoofed DTLS records, to cause legitimate packets to
    be dropped. (CVE-2016-2181)

  - An overflow condition exists in the BN_bn2dec() function
    in bn_print.c due to improper validation of
    user-supplied input when handling BIGNUM values. An
    unauthenticated, remote attacker can exploit this to
    crash the process. (CVE-2016-2182)

  - A vulnerability exists, known as SWEET32, in the 3DES
    and Blowfish algorithms due to the use of weak 64-bit
    block ciphers by default. A man-in-the-middle attacker
    who has sufficient resources can exploit this
    vulnerability, via a 'birthday' attack, to detect a
    collision that leaks the XOR between the fixed secret
    and a known plaintext, allowing the disclosure of the
    secret text, such as secure HTTPS cookies, and possibly
    resulting in the hijacking of an authenticated session.
    (CVE-2016-2183)

  - A flaw exists in the tls_decrypt_ticket() function in
    t1_lib.c due to improper handling of ticket HMAC
    digests. An unauthenticated, remote attacker can exploit
    this, via a ticket that is too short, to crash the
    process, resulting in a denial of service.
    (CVE-2016-6302)

  - An integer overflow condition exists in the 
    MDC2_Update() function in mdc2dgst.c due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this to cause a heap-based
    buffer overflow, resulting in a denial of service
    condition or possibly the execution of arbitrary code.
    (CVE-2016-6303)

  - A flaw exists in the ssl_parse_clienthello_tlsext()
    function in t1_lib.c due to improper handling of overly
    large OCSP Status Request extensions from clients. An
    unauthenticated, remote attacker can exploit this, via
    large OCSP Status Request extensions, to exhaust memory
    resources, resulting in a denial of service condition.
    (CVE-2016-6304)

  - An out-of-bounds read error exists in the certificate
    parser that allows an unauthenticated, remote attacker
    to cause a denial of service via crafted certificate
    operations. (CVE-2016-6306)

  - A flaw exists in the GOST ciphersuites due to the use of
    long-term keys to establish an encrypted connection. A
    man-in-the-middle attacker can exploit this, via a Key
    Compromise Impersonation (KCI) attack, to impersonate
    the server. (VulnDB 144759)

  - A denial of service vulnerability exists in x509_vfy.c
    due to improper handling of certificate revocation lists
    (CRLs). An unauthenticated, remote attacker can exploit
    this, via a specially crafted CRL, to cause a NULL 
    pointer dereference, resulting in a crash of the
    service. (CVE-2016-7052)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/openssl_advisory21.asc");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160922.txt");
  # https://github.com/openssl/openssl/commit/41b42807726e340538701021cdc196672330f4db
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09b29b30");
  script_set_attribute(attribute:"see_also", value:"https://sweet32.info/");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/blog/blog/2016/08/24/sweet32/");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the IBM AIX website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

include("aix.inc");
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
oslevel = get_kb_item_or_exit("Host/AIX/version");
if ( oslevel != "AIX-5.3" && oslevel != "AIX-6.1" && oslevel != "AIX-7.1" && oslevel != "AIX-7.2" )
{
  oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
  audit(AUDIT_OS_NOT, "AIX 5.3 / 6.1 / 7.1 / 7.2", oslevel);
}

if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

flag = 0;

#1.0.1.517
if (aix_check_package(release:"5.3", package:"openssl.base", minpackagever:"1.0.1.500", maxpackagever:"1.0.1.516", fixpackagever:"1.0.1.517") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssl.base", minpackagever:"1.0.1.500", maxpackagever:"1.0.1.516", fixpackagever:"1.0.1.517") > 0) flag++;
if (aix_check_package(release:"7.1", package:"openssl.base", minpackagever:"1.0.1.500", maxpackagever:"1.0.1.516", fixpackagever:"1.0.1.517") > 0) flag++;
if (aix_check_package(release:"7.2", package:"openssl.base", minpackagever:"1.0.1.500", maxpackagever:"1.0.1.516", fixpackagever:"1.0.1.517") > 0) flag++;

#1.0.2.1000
if (aix_check_package(release:"5.3", package:"openssl.base", minpackagever:"1.0.2.500", maxpackagever:"1.0.2.800", fixpackagever:"1.0.2.1000") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssl.base", minpackagever:"1.0.2.500", maxpackagever:"1.0.2.800", fixpackagever:"1.0.2.1000") > 0) flag++;
if (aix_check_package(release:"7.1", package:"openssl.base", minpackagever:"1.0.2.500", maxpackagever:"1.0.2.800", fixpackagever:"1.0.2.1000") > 0) flag++;
if (aix_check_package(release:"7.2", package:"openssl.base", minpackagever:"1.0.2.500", maxpackagever:"1.0.2.800", fixpackagever:"1.0.2.1000") > 0) flag++;

#20.13.101.500
if (aix_check_package(release:"5.3", package:"openssl.base", minpackagever:"20.11.101.500", maxpackagever:"20.13.101.499", fixpackagever:"20.13.101.500") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssl.base", minpackagever:"20.11.101.500", maxpackagever:"20.13.101.499", fixpackagever:"20.13.101.500") > 0) flag++;
if (aix_check_package(release:"7.1", package:"openssl.base", minpackagever:"20.11.101.500", maxpackagever:"20.13.101.499", fixpackagever:"20.13.101.500") > 0) flag++;
if (aix_check_package(release:"7.2", package:"openssl.base", minpackagever:"20.11.101.500", maxpackagever:"20.13.101.499", fixpackagever:"20.13.101.500") > 0) flag++;

#20.13.102.1000
if (aix_check_package(release:"5.3", package:"openssl.base", minpackagever:"20.13.102.0", maxpackagever:"20.13.102.999", fixpackagever:"20.13.102.1000") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssl.base", minpackagever:"20.13.102.0", maxpackagever:"20.13.102.999", fixpackagever:"20.13.102.1000") > 0) flag++;
if (aix_check_package(release:"7.1", package:"openssl.base", minpackagever:"20.13.102.0", maxpackagever:"20.13.102.999", fixpackagever:"20.13.102.1000") > 0) flag++;
if (aix_check_package(release:"7.2", package:"openssl.base", minpackagever:"20.13.102.0", maxpackagever:"20.13.102.999", fixpackagever:"20.13.102.1000") > 0) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : aix_report_get()
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl.base");
}
