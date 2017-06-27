#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10360);
  script_version ("$Revision: 1.28 $");
  script_cve_id("CVE-1999-0191");
  script_bugtraq_id(1818);
  script_osvdb_id(275);

  script_name(english:"Microsoft IIS newdsn.exe Arbitrary File Creation");
  script_summary(english:"Checks for the presence of /scripts/tools/newdsn.exe");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to an access control breach.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The CGI /scripts/tools/newdsn.exe is present.

This CGI allows any attacker to create files anywhere on your system if your
NTFS permissions are not tight enough, and can be used to overwrite DSNs of
existing databases."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Remove newdsn.exe"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(
    attribute:'see_also',
    value:'http://seclists.org/bugtraq/1997/Sep/70'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/04/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "1997/08/27");
 script_cvs_date("$Date: 2016/11/23 20:31:33 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Settings/ParanoidReport", "www/iis");
  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 )
 exit(0, "This script only runs in 'paranoid' mode as it is prone to false positive.");

port = get_http_port(default:80);
b = get_http_banner(port: port, exit_on_fail: 1);
if ("IIS" >!< b) exit(0, "The web server on port "+port+" is not IIS.");

cgi = "/scripts/tools/newdsn.exe";
res = is_cgi_installed3(item:cgi, port:port);
if(res)security_hole(port);
