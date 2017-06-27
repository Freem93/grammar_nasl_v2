#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10470);
  script_version ("$Revision: 1.20 $");
  script_cve_id("CVE-2000-0642");
  script_bugtraq_id(1497);
  script_osvdb_id(369);

  script_name(english:"WebActive HTTP Server active.log Remote Information Disclosure");
  script_summary(english:"Requests /active.log");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to information disclosure.'
  );

  script_set_attribute(
    attribute:'description',
    value:"It is possible to obtain the remote WebActive logfile by
requesting the file /active.log

An attacker may use this to obtain valuable information about
your site, such as who visits it and how popular it is."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Use another web server, as WebActive is not maintained.
If you are using WindowsNT, then remove read access to this
file."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/07/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/07/11");
 script_cvs_date("$Date: 2011/03/14 21:48:15 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2000-2011 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("http_version.nasl");
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
w = http_send_recv3(method:"GET", item:"/active.log", port:port);
if (isnull(w)) exit(0);
r = strcat(w[0], w[1], '\r\n', w[2]);
if("WEBactive Http Server" >< r)
  {
    security_warning(port);
  }
