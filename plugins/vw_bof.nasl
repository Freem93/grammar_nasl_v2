#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10650);
 script_version("$Revision: 1.33 $");
 script_cvs_date("$Date: 2016/11/03 14:16:36 $");

 script_cve_id("CVE-2001-0432");
 script_bugtraq_id(2579);
 script_osvdb_id(539);

 script_name(english:"Trend Micro InterScan VirusWall catinfo CGI Overflow");
 script_summary(english:"Overflow in catinfo");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a buffer
overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote cgi /catinfo seems to be vulnerable to a buffer overflow
when it receives a too long input strings, allowing any user to
execute arbitrary commands as root.

This CGI usually comes with the VirusWall suite.");
 #https://web.archive.org/web/20020227081400/http://archives.neohapsis.com/archives/bugtraq/2001-04/0218.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9986ffc0");
 script_set_attribute(attribute:"solution", value:
"If you are using VirusWall, upgrade to version 3.6, or else you *may*
ignore this warning.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/04/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/04/16");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);

 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_keys("Settings/ParanoidReport", "www/cern");
 script_require_ports("Services/www", 1812);

 exit(0);
}

# We can not determine if the overflow actually took place or
# not (as it took place when the CGI attempts to exit), so
# we check if the cgi dumbly spits a 2048 octets long name.
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:1812);

res = http_send_recv3(method:"GET", item:"/catinfo", port:port, exit_on_fail: 1);

# Send some crap...

res = http_send_recv3(method:"GET", item:string("/catinfo?", crap(2048)), port:port);
if("404" >< res[0]) exit(0,"Error 404 received.");

if(crap(2048) >< res[2])
  security_hole(port);
