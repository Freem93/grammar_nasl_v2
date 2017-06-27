#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(66270);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/02/03 17:40:02 $");

  script_cve_id(
    "CVE-2012-2686",
    "CVE-2013-0166",
    "CVE-2013-0169",
    "CVE-2013-0452",
    "CVE-2013-0453"
  );
  script_bugtraq_id(57755, 57778, 58632, 58661);
  script_osvdb_id(89848, 89865, 89866, 91577, 91659);

  script_name(english:"IBM Tivoli Endpoint Manager Server < 8.2.1372 Multiple Vulnerabilities");
  script_summary(english:"Checks version of the Tivoli Endpoint Manager Server.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of IBM Tivoli Endpoint Manager
Server prior to 8.2.1372. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple SSL related denial of service vulnerabilities
    exist. (CVE-2012-2686, CVE-2013-0166)

  - An SSL side-channel timing analysis attack allows full
    or partial plaintext recovery by a third-party listener.
    (CVE-2013-0169)

  - A cross-site request forgery vulnerability exists in the
    Use Analysis Application that can be exploited via a
    specially crafted AMF message. (CVE-2013-0452)

  - An unspecified cross-site scripting vulnerability exists
    in IBM Tivoli Endpoint Manager Web Reports.
    (CVE-2013-0453)");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_tivoli_endpoint_manager_for_software_use_cve_2013_04521?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9cffc3c2");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_cross_site_scripting_xss_vulnerability_was_discovered_in_web_reports_cve_2013_045328
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95af2b32");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_tivoli_endpoint_manager_tls_1_1_and_1_2_aes_ni_crash_cve_2012_26865
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c698ba83");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?rs=1015&uid=swg21633352");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?rs=1015&uid=swg21633354");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?rs=1015&uid=swg21633351");
  script_set_attribute(attribute:"solution", value:"Upgrade to Tivoli Endpoint Manager Server 8.2.1372 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
  
script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_endpoint_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("ibm_tem_detect.nasl");
  script_require_keys("www/BigFixHTTPServer");
  script_require_ports("Services/www", 52311);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = "IBM Tivoli Endpoint Manager";
port = get_http_port(default:52311, embedded:FALSE);

version = get_kb_item_or_exit("www/BigFixHTTPServer/"+port+"/version");
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, app_name, port);
if (version !~ "^(\d+\.){2,}\d+$") audit(AUDIT_VER_NOT_GRANULAR, app_name, port, version);

fix = "8.2.1372";

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

  if (report_verbosity > 0)
  {
    report = "";

    source = get_kb_item("www/BigFixHTTPServer/"+port+"/source");
    if (!isnull(source))
      report += '\n  Source            : ' + source;

    report +=
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
