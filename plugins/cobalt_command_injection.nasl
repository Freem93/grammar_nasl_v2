#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100387);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/26 15:15:34 $");

 script_name(english:"Cobalt RaQ4 Administrative Interface backup.cgi Command Execution (EXTINCTSPINACH)");
 script_summary(english:"Checks for the presence of a CGI.");

 script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a command
execution vulnerability.");
 script_set_attribute(attribute:"description", value:
"The Cobalt RaQ4 administrative interface running on the remote host
is affected by a remote command execution vulnerability in the
/cgi-bin/.cobalt/backup/backup.cgi script. An unauthenticated, remote
attacker can exploit this to execute arbitrary commands.

EXTINCTSPINACH is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2017/04/08 by a group known as the Shadow
Brokers.

Note that Nessus has not attempted to exploit this issue but has
instead only confirmed the presence of the backup.cgi script.");
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for a patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 # https://blog.malwarebytes.com/cybercrime/2017/04/shadowbrokers-fails-to-collect-1m-bitcoins-releases-stolen-information/
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b84a0bd");
 script_set_attribute(attribute:"see_also", value:"https://github.com/x0rz/EQGRP/blob/master/Linux/up/extinctspinach.txt");

 script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/24");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/h:sun:cobalt_raq_4");
 script_set_attribute(attribute:"in_the_news", value:"true");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

 script_dependencies("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 81, 444);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

res = is_cgi_installed3(item:"/cgi-bin/.cobalt/backup/backup.cgi", port:port);
if(res) security_report_v4(port:port, severity:SECURITY_HOLE);
else audit(AUDIT_NOT_DETECT, "backup.cgi");


