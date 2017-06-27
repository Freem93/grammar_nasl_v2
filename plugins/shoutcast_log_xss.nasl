#
# (C) Tenable Network Security, Inc.
#
# Ref: http://www.securitytracker.com/alerts/2003/Mar/1006203.html
#

include("compat.inc");

if (description)
{
 script_id(11624); 
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2015/01/15 03:38:17 $");

 script_osvdb_id(51504);
 
 script_name(english:"SHOUTcast Server Admin Log File XSS");
 script_summary(english:"SHOUTcast version check");

 script_set_attribute(attribute:"synopsis",value:
"The remote streaming audio server is affected by a cross-site scripting
vulnerability.");
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of SHOUTcast Server installed on
the remote host is earlier than 1.9.5.  Such versions do not properly
validate user input before storing it in its log file.  An attacker may
use this flaw to perform a cross-site scripting attack against the
administrators of the remote service and steal the administrators'
cookies.");
 script_set_attribute( attribute:"see_also", value:"http://www.securiteam.com/securitynews/5WP010U9FY.html");
 script_set_attribute(attribute:"solution", value:"Upgrade to SHOUTcast 1.9.5 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/12");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:nullsoft:shoutcast_server");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");

 script_dependencies("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 8000);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

url = '/content/dsjkdjfljk.mp3';
ports = add_port_in_list(list:get_kb_list("Services/www"), port:8000);
foreach port (ports)
{
 if (get_port_state(port))
 {
  r = http_send_recv3(port:port, method: 'GET', item: url, version: 10);
  if (! isnull(r))
  {
  if (egrep(pattern:"SHOUTcast Distributed Network Audio Server.*v(0\.|1\.[0-8]\.|1\.9\.[0-4][^0-9])", string: r[1]+r[2]) )
  {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
   exit(0);
  }
  }
 }
}
