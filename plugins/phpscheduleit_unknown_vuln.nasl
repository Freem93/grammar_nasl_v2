#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15772);
 script_version("$Revision: 1.16 $");
 script_cve_id("CVE-2004-2469");
 script_bugtraq_id(11690);
 script_osvdb_id(11840);
 
 script_name(english:"phpScheduleIt < 1.0.1 Reservation.class.php Arbitrary Reservation Modification");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
security bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of phpScheduleIt on the remote
host is earlier than 1.0.1.  Such versions are reportedly vulnerable
to an undisclosed issue that may allow an attacker to modify or delete
reservations." );
  # http://sourceforge.net/tracker/index.php?func=detail&aid=1051841&group_id=95547&atid=611778
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91b81e79" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpScheduleIt 1.0.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/10/21");
 script_cvs_date("$Date: 2012/09/12 01:59:49 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:brickhost:phpscheduleit");
script_end_attributes();

 
 script_summary(english:"Checks for the presence of a vulnerability in phpScheduleIt");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("phpscheduleit_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

# Check an install.
install = get_kb_item(string("www/", port, "/phpscheduleit"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  ver = matches[1];
  if ( ereg(pattern:"^(0\.|1\.0\.0)", string:ver)) 
    security_warning(port);
}

