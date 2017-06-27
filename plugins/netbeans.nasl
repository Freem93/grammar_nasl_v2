#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2016/04/01. Webmirror3.nbin will identify browsable
# directories.

include("compat.inc");

if(description)
{
 script_id(10149);
 script_version ("$Revision: 1.33 $");
 script_cvs_date("$Date: 2016/12/30 22:07:39 $");

 script_cve_id("CVE-1999-1527");
 script_bugtraq_id(816);
 script_osvdb_id(115);

 script_name(english:"Sun NetBeans Java IDE HTTP Server IP Restriction Bypass Arbitrary File/Directory Access (deprecated)");
 script_summary(english:"Determines whether the remote root directory is browsable.");
 
 script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
 script_set_attribute(attribute:"description", value:
"The remote host is running NetBeans (recently renamed to 'Forte') Java
IDE. There is a bug in this version that allows anyone to browse the
files on this system.

This plugin has been deprecated. Webmirror3 (plugin ID 10662) will
identify a browsable directory.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");

 script_set_attribute(attribute:"vuln_publication_date", value: "1999/11/23");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/11/24");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:sun:netbeans_developer");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:sun:forte:community_1.0_beta");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "httpver.nasl");
 script_require_ports("Services/www", 80, 8082);

 exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Webmirror3 (plugin ID 10662) will identify a browsable directory.");

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function netbeans(port)
{
local_var data, data_low, seek;

  data = http_get_cache(item:"/", port:port);
  if (isnull(data)) return;
  data_low = tolower(data);
  seek = "<title>index of /</title>";
  if(seek >< data_low)
  {
   if("netbeans" >< data_low) { 
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/content/directory_index', value: '/');
	}
   }
}

#
# NetBeans might be running on another port.
# 
if ( thorough_tests ) netbeans(port:8082);

port = get_http_port(default:80);
if (port != 8082 || ! thorough_tests) netbeans(port:port);
