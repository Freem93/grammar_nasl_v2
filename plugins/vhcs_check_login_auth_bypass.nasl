#
# (C) Tenable Network Security, Inc.
#

# NB: the project initially released an incomplete fix for this, which 
#     prevented unauthenticated but not authenticated users from 
#     exploiting the flaw. Unfortunately, the plugin can't check for
#     the incomplete fix because we don't have credentials.



include("compat.inc");

if (description)
{
  script_id(22078);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2006-0685");
  script_bugtraq_id(16600);
  script_osvdb_id(23108);

  script_name(english:"VHCS login.php check_login() Function Authentication Bypass");
  script_summary(english:"Tries to access a restricted script using VHCS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to an
authentication bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running VHCS, a control panel for hosting
providers. 

The GUI portion of the version of VHCS installed on the remote host
does not halt script execution if 'check_login()' fails.  An attacker
can leverage this flaw to bypass authentication and access VHCS
application scripts that would otherwise be restricted." );
 script_set_attribute(attribute:"see_also", value:"http://www.rs-labs.com/adv/RS-Labs-Advisory-2006-1.txt" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2006/Feb/174" );
 script_set_attribute(attribute:"see_also", value:"http://www.rs-labs.com/exploitsntools/rs_vhcs_simple_poc.html" );
 script_set_attribute(attribute:"see_also", value:"http://vhcs.net/new/modules/news/article.php?storyid=25" );
 script_set_attribute(attribute:"solution", value:
"Apply Security Patch 2006-02-09 referenced in the project advisory
above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/07/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/11");
 script_cvs_date("$Date: 2016/11/03 14:16:36 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/vhcs2", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to access a protected admin script.
  r = http_send_recv3(method:"GET", item:string(dir, "/admin/ip_manage.php"), port:port);
  if (isnull(r)) exit(0);

  # There's a problem if...
  if (
    # we're redirected to ../index.php and...
    "Location: ../index.php" >< r[1] &&
    # the result looks like the Manage IPs page.
    ' <form name="add_new_ip_frm' >< r[2]
  )
  {
    security_hole(port);
    exit(0);
  }
}
