#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(11817);
  script_version("$Revision: 1.17 $");
  script_bugtraq_id(8385);
  script_osvdb_id(2396);

  script_name(english:"Stellar Docs Malformed Query Path Disclosure");
  script_summary(english:"SQL Injection and more.");
  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to information disclosure.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote host is running StellarDocs

There is a flaw in this system which may allow an attacker to
obtain the physical path of the remote installation of StellarDocs.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to the latest version of this software'
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.securityfocus.com/archive/1/332565'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/08/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/08/12");
 script_cvs_date("$Date: 2016/12/14 20:33:27 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);


function check(dir)
{
  local_var	w, buf;
  w = http_send_recv3(method:"GET", item:dir + "/data/fetch.php?page='", port:port);
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  buf = strcat(w[0], w[1], '\r\n', w[2]);

  if("mysql_num_rows()" >< buf)
  	{
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
	}
 return(0);
}

foreach dir (cgi_dirs())
{
 check(dir:dir);
}
