#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10494);
  script_bugtraq_id(1587);
  script_osvdb_id(393);
  script_version ("$Revision: 1.28 $");
  script_cve_id("CVE-2000-0782");

  script_name(english:"Netwin Netauth netauth.cgi Traversal Arbitrary File Access");
  script_summary(english:"Checks for the presence of /cgi-bin/netauth.cgi" );

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is prone to an authentication bypass issue.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The 'Netauth' CGI is installed.  This CGI has a well-known security
flaw that lets an attacker read arbitrary files with the privileges of
the http daemon (usually root or nobody)."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to Netwin Netauth 4.2f or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");

  script_set_attribute(
    attribute:'see_also',
    value:'http://netwinsite.com/netauth/updates.htm'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/08/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/08/17");
 script_cvs_date("$Date: 2016/11/23 20:31:33 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:netwin:netauth");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

foreach dir (cgi_dirs())
{
 data = string(dir,  "/netauth.cgi?cmd=show&page=../../../../../../../../../etc/passwd");
 w = http_send_recv3(method:"GET", item:data, port:port);
 if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
 buf = strcat(w[0], w[1], '\r\n', w[2]);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf))security_warning(port);
}
