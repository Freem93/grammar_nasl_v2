#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15469);
 script_version ("$Revision: 1.20 $");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");

 script_cve_id(
   "CVE-2004-1669", 
   "CVE-2004-1670", 
   "CVE-2004-1671", 
   "CVE-2004-1672", 
   "CVE-2004-1673", 
   "CVE-2004-1674"
 );
 script_bugtraq_id(11371);
 script_osvdb_id(
  9805,
  9806,
  9807,
  9808,
  9809,
  9810,
  9811,
  9812,
  9813,
  9814,
  11558,
  11559,
  11560,
  11561,
  11563,
  11564,
  11565
 );

 script_name(english:"IceWarp Web Mail Multiple Flaws (1)");
 script_summary(english:"Check the version of IceWarp WebMail");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a webmail application that is
affected by multiple flaws.");
 script_set_attribute(attribute:"description", value:
"The remote host is running IceWarp Web Mail - a webmail solution
available for the Microsoft Windows platform.

The remote version of this software is vulnerable to multiple 
input validation issues that could allow an attacker to compromise the
integrity of the remote host.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc61aa25");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/380446/30/0/threaded");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Sep/96");
 script_set_attribute(attribute:"solution", value:
"Upgrade to IceWarp Web Mail 5.3.0 or newer.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/10");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:icewarp:webmail");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 32000);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:32000);

res = http_send_recv3(method:"GET", item:"/mail/", port:port, exit_on_fail: 1);

if ('Merak Email Server</A><BR>IceWarp Web Mail' >< res[2])
{
 version = egrep(pattern:"IceWarp Web Mail [0-9]\.", string:res);
 if ( ! version ) exit(0, "IceWarp Web Mail is not installed on port "+port+".");
 version = ereg_replace(pattern:".*(IceWarp Web Mail [0-9.]*).*", string:version, replace:"\1");
 set_kb_item(name:"www/" + port + "/icewarp_webmail/version", value:version);
 if ( ereg(pattern:"IceWarp Web Mail ([0-4]\.|5\.[0-2]\.)", string:version) )
	security_hole(port);
}
