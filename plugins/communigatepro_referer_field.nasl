#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11567);
 script_version ("$Revision: 1.16 $");

 script_cve_id("CVE-2003-1481");
 script_bugtraq_id(7501);
 script_osvdb_id(50621);

 script_name(english:"CommuniGate Pro Referer Field Session Token Disclosure");
 script_summary(english:"Checks the version of the remote CommunigatePro web Server");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote service has a session hijacking vulnerability."
 );
 script_set_attribute( attribute:"description", value:
"The remote install of CommuniGate Pro, according to its version
number, is vulnerable to a flaw that could allow a remote attacker to
access the mailbox of a targeted user.

To exploit such a flaw, an attacker needs to send an email to its
victim with a link to an image hosted on a rogue server that will
store the Referer field sent by the user user-agent, which contains
the credentials used to access the victim's mailbox." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2003/May/60"
 );
 script_set_attribute(
   attribute:"solution",
   value:"Upgrade to CommuniGate Pro version 4.1b2 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(200);
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/05");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:communigate:communigate_pro_core_server");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_dependencies("find_service1.nasl", "http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

########

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(!banner)exit(0);
if(egrep(pattern:"^Server: CommuniGatePro/([0-3]\.|4\.0|4\.1b1)", string:banner))security_warning(port);

