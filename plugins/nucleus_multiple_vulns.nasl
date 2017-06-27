#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(15788);
  script_version ("$Revision: 1.15 $");
  script_bugtraq_id(11631);

  script_name(english:"Nucleus CMS < 3.15 Multiple Vulnerabilities");
  script_summary(english:"Nucleus Version Check");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to multiple flaws.'
  );

  script_set_attribute(attribute:'description', value:
"The remote host is running Nucleus CMS, an open source content 
management system.

The remote version of this software is vulnerable to various flaws 
that may allow an attacker to perform a cross-site scripting attack 
using the remote host and to perform a SQL injection attack on the 
remote database."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to Nucleus 3.15 or newer."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/23");
 script_cvs_date("$Date: 2015/02/11 21:07:50 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value: "cpe:/a:nucleus_group:nucleus_cms");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencie("nucleus_sql_injection.nasl");
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

port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/nucleus");
if ( ! kb ) exit(0, "Nucleus is not running on port "+port);
matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
version = matches[1];
if ( ereg(pattern:"^([0-2]|3\.0|3\.1([^0-9]|$)|3\.1[0-4])", string:version) )
{
     security_hole(port);
     set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
     set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}
