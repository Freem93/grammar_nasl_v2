#
# (C) Tenable Network Security, Inc.
# 

include("compat.inc");

if(description)
{
 script_id(38152);
 script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2016/11/17 21:12:12 $");

 script_cve_id("CVE-2009-1556");
 script_bugtraq_id(34629);
 script_osvdb_id(54207);
 
 script_name(english:"Linksys WVC54GCA Wireless-G '/img/main.cgi' Information Disclosure");
 script_summary(english:"Determine if the remote network camera is vulnerable to a flaw");

 script_set_attribute(attribute:"synopsis", value: 
"Authenticated users can elevate their privileges on the remote network
camera.");
 script_set_attribute(attribute:"description", value:
"The remote host is a Linksys WVC54GCA network camera. 

The version of the firmware of the remote camera contains a flaw that
allows authenticated users to download the .htpasswd file from the
remote host, which gives them the ability to crack the passwords of
other users, including the password of the administrator.");
 script_set_attribute(attribute:"solution", value:"Contact your vendor for a patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(200);
 script_set_attribute(attribute:"see_also", value:"http://www.gnucitizen.org/blog/hacking-linksys-ip-cameras-pt-2/");

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/24");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/h:cisco:wvc54gca");
 script_end_attributes();
 
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

 script_dependencies("network_camera_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 1);
if (!  port ) exit(0);
str = get_kb_item('www/'+port+'/webcam');
if ( ! str ) exit(0);
if ( 'WVC54GCA' >!< str ) exit(0);

# We can't test /img/main.cgi since it's password protected
# however /main.cgi contains the same flaw

# If the camera is not password protected, there's not much info to get
url = "/img/main.cgi";
res = http_send_recv3(method:"GET", item:url, port:port);
if ( isnull(res) ) exit(0);
if ( " 401 " >!< res[2] ) exit(0);

#
# The camera replies with a 200 code OK but the file content 
# contains a 403 error code
#
url = "/main.cgi?next_file=.foo";
res = http_send_recv3(method:"GET", item:url, port:port);
if ( isnull(res) ) exit(0);
if ( " 403 " >< res[2] ) exit(0);

url = "/main.cgi?next_file=%2efoo";
res = http_send_recv3(method:"GET", item:url, port:port);
if ( isnull(res) ) exit(0);
if ( " 403 " >!< res[2]  && ".foo" >< res[2] ) security_warning(port);
