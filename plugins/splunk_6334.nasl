#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90705);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/08/09 17:45:02 $");

  script_cve_id(
    "CVE-2015-7995",
    "CVE-2016-0702",
    "CVE-2016-0705",
    "CVE-2016-0797",
    "CVE-2016-0798",
    "CVE-2016-0799",
    "CVE-2016-0800"
  );
  script_bugtraq_id(
    77325,
    83705,
    83733,
    83754,
    83755,
    83763
  );
  script_osvdb_id(
    126901,
    134973,
    135096,
    135121,
    135149,
    135150,
    135151,
    136776,
    136777,
    136778,
    136779,
    136780,
    136781
  );
  script_xref(name:"CERT", value:"583776");

  script_name(english:"Splunk Enterprise < 5.0.15 / 6.0.11 / 6.1.10 / 6.2.9 / 6.3.3.4 or Splunk Light < 6.2.9 / 6.3.3.4 Multiple Vulnerabilities (DROWN)");
  script_summary(english:"Checks the version of Splunk Enterprise and Light.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the instance of Splunk hosted on the
remote web server is Enterprise 5.0.x prior to 5.0.15, 6.0.x prior to
6.0.11, 6.1.x prior to 6.1.10, 6.2.x prior to 6.2.9, 6.3.x prior to
6.3.3.4, Light 6.2.x prior to 6.2.9, or Light 6.3.x prior to 6.3.3.4.
It is, therefore, affected by the following vulnerabilities :

  - A type confusion error exists in the bundled version of
    libxslt in the xsltStylePreCompute() function due to
    improper handling of invalid values. A context-dependent
    attacker can exploit this, via crafted XML files, to
    cause a denial of service condition. (CVE-2015-7995)

  - A key disclosure vulnerability exists in the bundled
    version of OpenSSL due to improper handling of
    cache-bank conflicts on the Intel Sandy-bridge
    microarchitecture. An attacker can exploit this to gain
    access to RSA key information. (CVE-2016-0702)

  - A double-free error exists in the bundled version of
    OpenSSL due to improper validation of user-supplied
    input when parsing malformed DSA private keys. A remote
    attacker can exploit this to corrupt memory, resulting
    in a denial of service condition or the execution of
    arbitrary code. (CVE-2016-0705)

  - A NULL pointer dereference flaw exists in the bundled
    version of OpenSSL in the BN_hex2bn() and BN_dec2bn()
    functions. A remote attacker can exploit this to trigger
    a heap corruption, resulting in the execution of
    arbitrary code. (CVE-2016-0797)

  - A denial of service vulnerability exists in the bundled
    version of OpenSSL due to improper handling of invalid
    usernames. A remote attacker can exploit this, via a
    specially crafted username, to leak 300 bytes of memory
    per connection, exhausting available memory resources.
    (CVE-2016-0798)

  - Multiple memory corruption issues exist in the bundled
    version of OpenSSL that allow a remote attacker to cause
    a denial of service condition or the execution of
    arbitrary code. (CVE-2016-0799)

  - A flaw exists in the bundled version of OpenSSL that
    allows a cross-protocol Bleichenbacher padding oracle
    attack known as DROWN (Decrypting RSA with Obsolete and
    Weakened eNcryption). This vulnerability exists due to a
    flaw in the Secure Sockets Layer Version 2 (SSLv2)
    implementation, and it allows captured TLS traffic to be
    decrypted. A man-in-the-middle attacker can exploit this
    to decrypt the TLS connection by utilizing previously
    captured traffic and weak cryptography along with a
    series of specially crafted connections to an SSLv2
    server that uses the same private key. (CVE-2016-0800)

  - A flaw exists due to improper handling of specially
    crafted HTTP requests that contain specific headers. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (VulnDB 136776)

  - A flaw exists due to improper handling of malformed HTTP
    requests. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition.
    (VulnDB 136777)

  - A flaw exists that is triggered when directly accessing
    objects. An authenticated, remote attacker can exploit
    this to disclose search logs. (VulnDB 136778)

  - A flaw exists due to the failure to honor the
    sslVersions keyword for TLS protocol versions,
    preventing users from enforcing TLS policies.
    (VulnDB 136779)

  - A path traversal vulnerability exists in the 'collect'
    command due to improper sanitization of user-supplied
    input. An authenticated, remote attacker can exploit
    this, via a specially crafted request, to execute
    arbitrary code arbitrary code with the privileges of the
    user running the splunkd process. (VulnDB 136780)

  - A path traversal vulnerability exists in the 'inputcsv'
    and 'outputcsv' commands due to improper sanitization of
    user-supplied input. An authenticated, remote attacker
    can exploit this, via a specially crafted request, to
    can access or overwrite file paths. (VulnDB 136781)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.splunk.com/view/SP-CAAAPKV");
  script_set_attribute(attribute:"see_also", value:"https://drownattack.com/");
  script_set_attribute(attribute:"see_also", value:"https://www.drownattack.com/drown-attack-paper.pdf");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160301.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Splunk Enterprise 5.0.15 / 6.0.11 / 6.1.10 / 6.2.9 /
6.3.3.4 or later, or Splunk Light 6.2.9 / 6.3.3.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("splunkd_detect.nasl", "splunk_web_detect.nasl");
  script_require_ports("Services/www", 8089, 8000);
  script_require_keys("installed_sw/Splunk");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Splunk";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8000, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
ver = install['version'];
fix = FALSE;

install_url = build_url(qs:dir, port:port);

xss = FALSE;

# 5.0.x < 5.0.15
if (ver =~ "^5\.0($|[^0-9])")
  fix = '5.0.15';

# 6.0.x < 6.0.11
else if (ver =~ "^6\.0($|[^0-9])")
  fix = '6.0.11';

# 6.1.x < 6.1.10
else if (ver =~ "^6\.1($|[^0-9])")
  fix = '6.1.10';

# 6.2.x < 6.2.9
else if (ver =~ "^6\.2($|[^0-9])")
  fix = '6.2.9';

# 6.3.x < 6.3.3.4
else if (ver =~ "^6\.3($|[^0-9])")
  fix = '6.3.3.4';

if (fix && ver_compare(ver:ver,fix:fix,strict:FALSE) < 0)
{
  report =
    '\n  URL               : ' + install_url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(extra:report, port:port, severity:SECURITY_HOLE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, ver);
