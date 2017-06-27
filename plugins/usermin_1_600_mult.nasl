#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77706);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/23 22:03:56 $");

  script_cve_id("CVE-2014-3883", "CVE-2014-3884", "CVE-2014-3924");
  script_bugtraq_id(67649, 68131);
  script_osvdb_id(107312, 108283, 108292);

  script_name(english:"Usermin < 1.600 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Usermin.");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Usermin install
hosted on the remote web server is prior to 1.600. It is, therefore,
affected by the following vulnerabilities :

  - An unspecified remote command execution vulnerability.
    (CVE-2014-3883)

  - Multiple cross-site scripting (XSS) vulnerabilities.
    (CVE-2014-3924).");
  script_set_attribute(attribute:"see_also", value:"http://jvn.jp/en/jp/JVN92737498/index.html");
  script_set_attribute(attribute:"see_also", value:"http://www.webmin.com/uchanges.html");
  script_set_attribute(attribute:"solution", value:"Upgrade Usermin 1.600 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:webmin:usermin");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:usermin:usermin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("usermin_detect.nbin");
  script_require_keys("www/usermin", "Settings/ParanoidReport");
  script_require_ports("Services/www", 20000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

app = "Usermin";
port = get_http_port(default:20000, embedded: TRUE);

get_kb_item_or_exit('www/'+port+'/usermin');
version = get_kb_item_or_exit('www/usermin/'+port+'/version', exit_code:1);
source = get_kb_item_or_exit('www/usermin/'+port+'/source', exit_code:1);

dir = '/';
install_url = build_url(port:port, qs:dir);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = "1.600";

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] < 1) ||
  (ver[0] == 1 && ver[1] < 600)
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Version Source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
