#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  Date: Wed, 10 Apr 2002 08:05:53 +0400
#  From: Over_G <overg@mail.ru>
#  To: bugtraq@securityfocus.com
#  Subject: Disclosing information in Super GuestBook

include( 'compat.inc' );

if(description)
{
  script_id(11536);
  script_version ("$Revision: 1.14 $");
  script_bugtraq_id(7319);
  script_osvdb_id(4663);

  script_name(english:"Super Guestbook superguestconfig Admin Password Disclosure");
  script_summary(english:"Checks for superguestconfig");

   script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is prone to information disclosure.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote server is running Super GuestBook, a set of php
scripts to manage an interactive guestbook.

An attacker may retrieve the file /superguestconfig, which contains
the password of the guestbook administrator as well as other configuration
details.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Modify file permissions or access restrictions to prevent the download of superguestconfig.'
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.derkeiler.com/Mailing-Lists/securityfocus/bugtraq/2003-04/0161.html'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/04/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/04/10");
 script_cvs_date("$Date: 2016/12/14 20:33:27 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

dirs = make_list(cgi_dirs(),  "/sgb");

foreach d (dirs)
{
 w = http_send_recv3(method:"GET", item:string(d, "/superguestconfig"), port:port);
 if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
 res = strcat(w[0], w[1], '\r\n', w[2]);

 if("MultipleSign=" >< res &&
    "Header=" >< res &&
    "MyName=" >< res)
	{
 	 security_warning(port);
	 exit(0);
	 }
}
