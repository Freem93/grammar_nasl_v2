#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96145);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/02/21 15:06:14 $");

  script_cve_id(
    "CVE-2016-2177",
    "CVE-2016-2178",
    "CVE-2016-2183",
    "CVE-2016-2928",
    "CVE-2016-2931",
    "CVE-2016-2932",
    "CVE-2016-2933",
    "CVE-2016-2934",
    "CVE-2016-2935",
    "CVE-2016-2943",
    "CVE-2016-6304",
    "CVE-2016-6306"
  );
  script_bugtraq_id(
    91081,
    91319,
    92630,
    93150,
    93153,
    94983,
    94984,
    94986,
    94987,
    94989
  );
  script_osvdb_id(
    139313,
    139471,
    143387,
    143388,
    144687,
    144688,
    145367,
    145373,
    145376,
    145379,
    145382,
    145383,
    145384
  );
  script_xref(name:"IAVB", value:"2016-B-0191");

  script_name(english:"IBM BigFix Remote Control < 9.1.3 Multiple Vulnerabilities (SWEET32)");
  script_summary(english:"Checks the version of IBM BigFix Remote Control.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM BigFix Remote Control running on the remote host is
prior to 9.1.3. It is, therefore, affected by the multiple
vulnerabilities :

  - Multiple integer overflow conditions exist in the
    bundled version of OpenSSL in files s3_srvr.c,
    ssl_sess.c, and t1_lib.c due to improper use of pointer
    arithmetic for heap-buffer boundary checks. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service. (CVE-2016-2177)

  - An information disclosure vulnerability exists in the
    bundled version of OpenSSL in the dsa_sign_setup()
    function in dsa_ossl.c due to a failure to properly
    ensure the use of constant-time operations. An
    unauthenticated, remote attacker can exploit this, via a
    timing side-channel attack, to disclose DSA key
    information. (CVE-2016-2178)

  - A vulnerability exists, known as SWEET32, in the bundled
    version of OpenSSL in the 3DES and Blowfish algorithms
    due to the use of weak 64-bit block ciphers by default.
    A man-in-the-middle attacker who has sufficient
    resources can exploit this vulnerability, via a
    'birthday' attack, to detect a collision that leaks the
    XOR between the fixed secret and a known plaintext,
    allowing the disclosure of the secret text, such as
    secure HTTPS cookies, and possibly resulting in the
    hijacking of an authenticated session. (CVE-2016-2183)

  - An information disclosure vulnerability exists due to
    the inclusion of sensitive information in error logs. An
    authenticated, remote attacker can exploit this to
    disclose information. (CVE-2016-2928)

  - An information disclosure vulnerability exists due to
    the transmission of information in cleartext. A
    man-in-the-middle attacker can exploit this to disclose
    sensitive information. (CVE-2016-2931)

  - An unspecified flaw exists that allows an
    unauthenticated, remote attacker to inject arbitrary XML
    content. (CVE-2016-2932)

  - An information disclosure vulnerability exists due to a
    flaw that allows traversing outside of a restricted
    path. An authenticated, remote attacker can exploit
    this, via a specially crafted request, to disclose
    arbitrary files. (CVE-2016-2933)

  - A cross-site scripting (XSS) vulnerability exists due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2016-2934)

  - An unspecified flaw exists that allows an
    unauthenticated, remote attacker to submit invalid HTTP
    requests, resulting in a denial of service condition for
    the broker application. (CVE-2016-2935)

  - An information disclosure vulnerability exists due to
    the storage of information in log files in plaintext. A
    local attacker can exploit this to disclose sensitive
    information. (CVE-2016-2943)

  - A flaw exists in the bundled version of OpenSSL in the
    ssl_parse_clienthello_tlsext() function in t1_lib.c due
    to improper handling of overly large OCSP Status Request
    extensions from clients. An unauthenticated, remote
    attacker can exploit this, via large OCSP Status Request
    extensions, to exhaust memory resources, resulting in a
    denial of service condition. (CVE-2016-6304)

  - An out-of-bounds read error exists the bundled version
    of OpenSSL in the certificate parser that allows an
    unauthenticated, remote attacker to cause a denial of
    service via crafted certificate operations.
    (CVE-2016-6306)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21991882");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21991955");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21991892");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21991876");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21991870");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21991960");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21991951");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21991896");
  script_set_attribute(attribute:"see_also", value:"https://sweet32.info/");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/blog/blog/2016/08/24/sweet32/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM BigFix Remote Control version 9.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:bigfix_remote_control");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_remote_control");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("ibm_bigfix_remote_control.nbin");
  script_require_keys("installed_sw/IBM BigFix Remote Control");
  script_require_ports("Services/www", 80, 443, 9080, 9443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "IBM BigFix Remote Control";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
url = build_url(qs:dir, port:port);
fix = "9.1.3";

if (version == "9" || version == "9.1") audit(AUDIT_VER_NOT_GRANULAR, app, port, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);

security_report_v4(
    port:port,
    severity:SECURITY_HOLE,
    xss:TRUE,
    extra:
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n'
);
