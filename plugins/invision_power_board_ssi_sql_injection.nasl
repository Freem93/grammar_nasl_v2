#
# (C) Tenable Network Security, Inc.
#

# From: "JvdR" <thewarlock@home.nl>
# To: <bugtraq@securityfocus.com>
# Subject: Multiple Vulnerabilities in Invision Power Board v1.3.1 Final.
# Date: Tue, 8 Jun 2004 16:53:11 +0200
#

include("compat.inc");

if(description)
{
  script_id(12268);
  script_bugtraq_id(10511);
  script_osvdb_id(51279);
  script_version("$Revision: 1.16 $");
  name["english"] = "Invision Power Board ssi.php f Parameter SQL Injection";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"A vulnerability exists in the version of Invision Power Board on the
remote host such that unauthorized users can inject SQL commands
through the 'ssi.php' script.  An attacker may use this flaw to gain
the control of the remote database." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Jun/124" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/06/11");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:invisionpower:invision_power_board");
script_end_attributes();
 
  script_summary(english:"Detect Invision Power Board ssi.php SQL Injection");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencies("invision_power_board_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/invision_power_board");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  w = http_send_recv3(method:"GET", item:string(dir, "/ssi.php?a=out&type=xml&f=0)'"), port:port);
  if (isnull(w)) exit(1, "The web server did not answer");
  res = w[2];

  if ( "AND t.approved=1 ORDER BY t.last_post" >< res )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  }
}
