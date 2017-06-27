#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73639);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

  script_cve_id(
    "CVE-2013-4353",
    "CVE-2013-6449",
    "CVE-2013-6450",
    "CVE-2014-0160"
  );
  script_bugtraq_id(64530, 64618, 64691, 66690);
  script_osvdb_id(101347, 101597, 101843, 105465);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");

  script_xref(name:"HP", value:"SSRT101501");

  script_name(english:"HP System Management Homepage OpenSSL Multiple Vulnerabilities (Heartbleed)");
  script_summary(english:"Performs a banner check");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to the web server's banner, the version of HP System
Management Homepage (SMH) hosted on the remote web server has an
implementation of the OpenSSL library affected by the following issues :

  - An error exists in the 'ssl3_take_mac' function in the
    file 'ssl/s3_both.c' related to handling TLS handshake
    traffic that could lead to denial of service attacks.
    (CVE-2013-4353)

  - An error exists in the 'ssl_get_algorithm2' function in
    the file 'ssl/s3_lib.c' related to handling TLS 1.2
    traffic that could lead to denial of service attacks.
    (CVE-2013-6449)

  - An error exists related to the handling of DTLS
    retransmission processes that could lead to denial of
    service attacks. (CVE-2013-6450)

  - An out-of-bounds read error, known as the 'Heartbleed
    Bug', exists related to handling TLS heartbeat
    extensions that could allow an attacker to obtain
    sensitive information such as primary key material,
    secondary key material, and other protected content.
    (CVE-2014-0160)");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  # https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04239372
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?383250e9");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/532007/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/532095/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP System Management Homepage 7.2.3.1 (Linux or Windows) /
7.3.2.1(B) (Windows) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/18");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:system_management_homepage");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("compaq_wbem_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("www/hp_smh");
  script_require_ports("Services/www", 2301, 2381);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

# Only Linux and Windows are affected -- HP-UX is not mentioned
if (report_paranoia < 2)
{
  os = get_kb_item_or_exit("Host/OS");
  if ("Windows" >!< os && "Linux" >!< os) audit(AUDIT_OS_NOT, "Windows or Linux", os);
}

port    = get_http_port(default:2381, embedded:TRUE);
install = get_install_from_kb(appname:'hp_smh', port:port, exit_on_fail:TRUE);
dir     = install['dir'];
version = install['ver'];
prod    = get_kb_item_or_exit("www/"+port+"/hp_smh/variant");

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, prod, build_url(port:port, qs:dir+"/") );

# nb: 'version' can have non-numeric characters in it so we'll create
#     an alternate form and make sure that's safe for use in 'ver_compare()'.
version_alt = ereg_replace(pattern:"[_-]", replace:".", string:version);
if (!ereg(pattern:"^[0-9][0-9.]+$", string:version_alt)) exit(1, 'The version of '+prod+' installed at '+build_url(port:port, qs:dir+"/")+' does not look valid ('+version+').');

if (
  version_alt =~ "^7\.1\.2($|[^0-9])" ||
  (version_alt =~ "^7\.2($|[^0-9])" && ver_compare(ver:version_alt, fix:"7.2.3.1", strict:FALSE) == -1) ||
  (version_alt =~ "^7\.3($|[^0-9])" && ver_compare(ver:version_alt, fix:"7.3.2.1", strict:FALSE) == -1)
)
{
  if (report_verbosity > 0)
  {
    source_line = get_kb_item("www/"+port+"/hp_smh/source");

    report = '\n  Product           : ' + prod;
    if (!isnull(source_line))
      report += '\n  Version source    : ' + source_line;
    report +=
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.2.3.1 / 7.3.2.1' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, prod, port, version);
