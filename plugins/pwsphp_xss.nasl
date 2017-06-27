#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18216);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2005-1508");
  script_bugtraq_id(13561, 13563);
  script_osvdb_id(16228, 16229, 16230, 16231, 16232);

  script_name(english:"PwsPHP profil.php id Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to cross-site scripting." );
 script_set_attribute(attribute:"description", value:
"The remote host runs PWSPHP (Portail Web System) a CMS written in PHP.

The remote version  of this software is vulnerable to cross-site 
scripting attack due to a lack of sanity checks on the 'skin' parameter
in the script SettingsBase.php.

With a specially crafted URL, an attacker could use the remote server
to set up a cross-site scripting attack." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.2.3 or newer" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/07");
 script_cvs_date("$Date: 2016/01/07 15:01:56 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_summary(english:"Checks XSS in PWSPHP");
  script_category(ACT_GATHER_INFO);
  
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses : XSS");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);
if(!can_host_php(port:port)) exit(0);

if(get_port_state(port))
{
   foreach d ( cgi_dirs() )
   {
    buf = http_get(item:string(d,"/profil.php?id=1%20<script>foo</script>"), port:port);
    r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
    if( r == NULL )exit(0);
    if("title>PwsPHP " >< r && (egrep(pattern:"<script>foo</script>", string:r)))
    {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
   }
}
