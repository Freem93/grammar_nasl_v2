#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(14194);
  script_version ("$Revision: 1.19 $");
  script_cve_id("CVE-2004-2056");
  script_bugtraq_id(10798);
  script_osvdb_id(8258);

  script_name(english:"Nucleus CMS action.php itemid Parameter SQL Injection");
  script_summary(english:"Nucleus Version Check");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is prone to a SQL injection.'
  );

  script_set_attribute(attribute:'description', value:
"The remote host is running Nucleus CMS, an open source content 
management system.

There is a SQL injection condition in the remote version of this 
software that could allow an attacker to execute arbitrary SQL 
commands against the remote database.

An attacker could exploit this flaw to gain unauthorized access to 
the remote database and gain admin privileges on the remote CMS."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to Nucleus 3.1 or newer."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(
    attribute:'see_also',
    value:'http://marc.info/?l=bugtraq&m=109087144509299&w=2'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/07/25");
 script_cvs_date("$Date: 2016/11/23 20:31:34 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value: "cpe:/a:nucleus_group:nucleus_cms");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
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

foreach dir (cgi_dirs())
{
 w = http_send_recv3(method:"GET", item: dir+"/index.php", port:port, exit_on_fail: 1);
 res = strcat(w[0], w[1], '\r\n', w[2]);
 if ('"generator" content="Nucleus' >< res )
 {
     line = egrep(pattern:"generator.*content=.*Nucleus v?([0-9.]*)", string:res);
     version = ereg_replace(pattern:".*generator.*content=.*Nucleus v?([0-9.]*).*", replace:"\1", string:line);
     if ( version == line ) version = "unknown";
     if ( dir == "" ) dir = "/";

     set_kb_item(name:"www/" + port + "/nucleus", value:version + " under " + dir );

    if ( ereg(pattern:"^([0-2]|3\.0)", string:version) )
    {
     security_hole(port);
     set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
     exit(0);
    }
 }
}
