#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(55134);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/02/11 21:07:49 $");

  script_cve_id("CVE-2011-1264");
  script_bugtraq_id(48175);
  script_osvdb_id(72937);
  script_xref(name:"MSFT", value:"MS11-052");
  script_xref(name:"IAVB", value:"2011-B-0068");

  script_name(english:"MS11-051: Vulnerability in Active Directory Certificate Services Web Enrollment Could Allow Elevation of Privilege (2518295) (uncredentialed check)");
  script_summary(english:"Tries to run a command via ADOdb Lite's adodb-perf-module.inc.php");

  script_set_attribute(attribute:"synopsis", value:
"The remote Active Directory Certificate Services Web Enrollment
server is vulnerable to a cross-site scripting attack." );
  script_set_attribute(attribute:"description", value:
"Active Directory Certificate Services Web Enrollment is installed on
the remote host.

The remote version of this software is vulnerable to a cross-site
scripting vulnerability that could allow an attacker to inject a
client-side script into the user's web browser instance.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-051");
  script_set_attribute(attribute:"solution", value:"Install patch MS11-051 from Microsoft.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "microsoft_certsrv_anon_detect.nasl");
  script_require_keys("www/ms_cert_srv");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80);
ret = get_install_from_kb(appname:'ms_cert_srv', port:port, exit_on_fail:TRUE);

r = http_send_recv3(
  method:"GET",
  port: port,
  item:ret['dir'] + '/certrqxt.asp',
  add_headers:make_array("User-Agent", '";<<<' + SCRIPT_NAME + ">>>" ),
  exit_on_fail:TRUE
);
if ( r[0] =~ "HTTP/.* 200 " &&
     'sAttrib+="UserAgent:";<<<' + SCRIPT_NAME + '>>>\\r\\n"' >< r[2] )
  {
 	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	security_warning(port);
  }
else exit(0, "The web server listening on port "+port+" is not affected.");
