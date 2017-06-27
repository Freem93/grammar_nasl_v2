#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96771);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/01/27 15:06:51 $");

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
    "CVE-2016-6306"
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
    93153
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
    144688
  );

  script_name(english:"MySQL Enterprise Monitor 3.3.x < 3.3.1.1112 Multiple Vulnerabilities (SWEET32) (January 2017 CPU)");
  script_summary(english:"Checks the version of MySQL Enterprise Monitor.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the MySQL Enterprise Monitor
application running on the remote host is 3.3.x prior to 3.3.1.1112.
It is, therefore, affected by multiple vulnerabilities in the bundled
version of OpenSSL :

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

  - A denial of service vulnerability exists in the 
    ssl_parse_clienthello_tlsext() function in t1_lib.c due
    to improper handling of overly large OCSP Status Request
    extensions from clients. An unauthenticated, remote
    attacker can exploit this, via large OCSP Status Request
    extensions, to exhaust memory resources. (CVE-2016-6304)

  - An out-of-bounds read error exists in the certificate
    parser that allows an unauthenticated, remote attacker
    to cause a denial of service via crafted certificate
    operations. (CVE-2016-6306)");
  # https://dev.mysql.com/doc/relnotes/mysql-monitor/3.3/en/news-3-3-1.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84dbc0d1");
  # http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1c38e52");
  script_set_attribute(attribute:"see_also", value:"https://sweet32.info/");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/blog/blog/2016/08/24/sweet32/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL Enterprise Monitor version 3.3.1.1112 or later as
referenced in the January 2017 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_enterprise_monitor");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("mysql_enterprise_monitor_web_detect.nasl");
  script_require_keys("installed_sw/MySQL Enterprise Monitor", "Settings/ParanoidReport");
  script_require_ports("Services/www", 18443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app  = "MySQL Enterprise Monitor";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:18443);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];
install_url = build_url(port:port, qs:"/");

fix = "3.3.1.1112";
vuln = FALSE;
if (version =~ "^3\.3($|[^0-9])" && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
  vuln = TRUE;;

if (vuln)
{
  report =
    '\n  URL               : ' + install_url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
