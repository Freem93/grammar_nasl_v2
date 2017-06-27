#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85581);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_cve_id(
    "CVE-2015-1788",
    "CVE-2015-1789",
    "CVE-2015-1790",
    "CVE-2015-1791",
    "CVE-2015-1792",
    "CVE-2015-1793"
  );
  script_bugtraq_id(
    75154,
    75156,
    75157,
    75158,
    75161,
    75652
  );
  script_osvdb_id(
    122875,
    123172, 
    123173, 
    123174,
    123175,
    124300,
    126171
  );

  script_name(english:"Splunk Enterprise < 5.0.14 / 6.0.10 / 6.1.9 / 6.2.5 or Splunk Light < 6.2.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Splunk Enterprise and Light.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the instance of Splunk hosted on the
remote web server is Enterprise 5.0.x prior to 5.0.14, 6.0.x prior to
6.0.10, 6.1.x prior to 6.1.9, 6.2.x prior to 6.2.5, or Light 6.2.x
prior to 6.2.5. It is, therefore, affected by the following
vulnerabilities in the bundled OpenSSL library :

  - A denial of service vulnerability exists when processing
    an ECParameters structure due to an infinite loop that
    occurs when a specified curve is over a malformed binary
    polynomial field. A remote attacker can exploit this to
    perform a denial of service against any system that
    processes public keys, certificate requests, or
    certificates. This includes TLS clients and TLS servers
    with client authentication enabled. (CVE-2015-1788)

  - A denial of service vulnerability exists due to improper
    validation of the content and length of the ASN1_TIME
    string by the X509_cmp_time() function. A remote
    attacker can exploit this, via a malformed certificate
    and CRLs of various sizes, to cause a segmentation
    fault, resulting in a denial of service condition. TLS
    clients that verify CRLs are affected. TLS clients and
    servers with client authentication enabled may be
    affected if they use custom verification callbacks.
    (CVE-2015-1789)

  - A NULL pointer dereference flaw exists in the PKCS#7
    parsing code due to incorrect handling of missing inner
    'EncryptedContent'. This allows a remote attacker, via
    specially crafted ASN.1-encoded PKCS#7 blobs with
    missing content, to cause a denial of service condition
    or other potential unspecified impacts. (CVE-2015-1790)

  - A double-free error exists due to a race condition that
    occurs when a NewSessionTicket is received by a
    multi-threaded client when attempting to reuse a
    previous ticket. (CVE-2015-1791)

  - A denial of service vulnerability exists in the CMS code
    due to an infinite loop that occurs when verifying a
    signedData message. A remote attacker can exploit this
    to cause a denial of service condition. (CVE-2015-1792)

  - A certificate validation bypass vulnerability exists due
    to a flaw in the X509_verify_cert() function in file
    x509_vfy.c, which occurs when locating alternate
    certificate chains whenever the first attempt to build
    such a chain fails. A remote attacker can exploit this,
    by using a valid leaf certificate as a certificate
    authority (CA), to issue invalid certificates that will
    bypass authentication. (CVE-2015-1793)

Additionally, a cross-site scripting vulnerability exists in Splunk
Enterprise due to improper validation of user-supplied input before
returning it to users. An attacker can exploit this, via a crafted
request, to execute arbitrary script code. (VulnDB 126171)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.splunk.com/view/SP-CAAAN84");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150611.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150709.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Splunk Enterprise 5.0.14 / 6.0.10 / 6.1.9 / 6.2.5 or later,
or Splunk Light 6.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("splunkd_detect.nasl","splunk_web_detect.nasl");
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

# 5.0.x < 5.0.14
if (ver =~ "^5\.0($|[^0-9])")
{
  fix = '5.0.14';
  xss = TRUE;
}
# 6.0.x < 6.0.10
else if (ver =~ "^6\.0($|[^0-9])")
{
  fix = '6.0.10';
  xss = TRUE;
}
# 6.1.x < 6.1.9
else if (ver =~ "^6\.1($|[^0-9])")
  fix = '6.1.9';

# 6.2.x < 6.2.5
else if (ver =~ "^6\.2($|[^0-9])")
  fix = '6.2.5';


if (fix && ver_compare(ver:ver,fix:fix,strict:FALSE) < 0)
{
  if (xss) set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, ver);
