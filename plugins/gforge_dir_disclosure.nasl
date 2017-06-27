#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(16225);
  script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2016/10/10 15:57:06 $");
  script_cve_id("CVE-2005-0299");
  script_bugtraq_id(12318);
  script_osvdb_id(13088, 13089);

  script_name(english:"GForge Multiple Script Traversal Arbitrary Directory Listing");
  script_summary(english:"Checks for a flaw in GForge");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a PHP application that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running GForge, a CVS repository browser written
in PHP. The installed version fails to properly sanitize user-supplied
data to the 'dir' URI parameter in the 'controller.php' script, or the
'dir_name' parameter in the 'controlleroo.php' script. An attacker
could exploit this flaw to disclose the content of arbitrary
directories stored on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Jan/242");
 script_set_attribute(attribute:"solution", value:"Upgrade to GForge 4.0.0 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/20");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/21");

script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:gforge:gforge");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("gforge_detect.nasl");
  script_require_keys("www/gforge");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, embedded: 0, php: 1);

install = get_install_from_kb(appname:'gforge', port:port);
if (isnull(install)) exit(0, "The 'www/"+port+"/gforge' KB item is missing.");

dir = install['dir'];

r = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

if ( "gforge.org" >< tolower(r[2]))
{
    for ( i = 0 ; i < 15 ; i ++ )
    {
      r = http_send_recv3(method:"GET", item:string(dir, "/scm/controlleroo.php?group_id=",i,"&dir_name=../../../../../../../../etc"), port:port, exit_on_fail: 1);
      if ( "passwd" >< r[2] &&
           "group"  >< r[2] &&
           "resolv.conf" >< r[2] &&
           "hosts" >< r[2] )
      {
        security_warning(port);
        exit(0);
      }
    }
    exit(0);
}
