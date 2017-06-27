#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(19753);
 script_version("$Revision: 1.14 $");

 script_bugtraq_id(14141);
 script_osvdb_id(7669);

 script_name(english:"phpGroupWare < 0.9.16 Addressbook Unspecified Vulnerability");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to an unspecified flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running PhpGroupWare, a multi-user
groupware suite written in PHP.

This version is prone to an unspecified flaw related to its addressbook." );
 script_set_attribute(attribute:"solution", value:
"Update to version 0.9.16.000 or newer." );
 script_set_attribute(attribute:"risk_factor", value:"Low");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"see_also", value:"http://www.phpgroupware.org/" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/06/06");
 script_cvs_date("$Date: 2016/11/23 20:42:23 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:phpgroupware:phpgroupware");
  script_end_attributes();

 script_summary(english:"Checks for PhpGroupWare version");

 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("phpgroupware_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/phpGroupWare");
if ( ! kb ) exit(0);

matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
if ( ereg(pattern:"^0\.([0-8]\.|9\.([0-9]\.|1[0-5]\.$))", string:matches[1]))
	security_note(port);
