#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33139);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2012/08/20 19:27:40 $");

  script_name(english:"WS-Management Server Detection");
  script_summary(english:"Sends an Identify request");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is used for remote management.");
  script_set_attribute(attribute:"description", value:
"The remote web server supports the Web Services for Management
(WS-Management) specification, a general web services protocol based
on SOAP for managing systems, applications, and other such entities.");
  script_set_attribute(attribute:"see_also", value:"http://www.dmtf.org/standards/wsman/");
  script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/WS-Management");
  script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2008-2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "find_service2.nasl");
  script_require_ports("Services/www", 8889);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_kb_item("Services/www");
if (!port) port = 8889;
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

banner = get_http_banner(port:port, broken:TRUE);
if (
  !banner || 
  (
    "405 Method not allowed" >!< banner &&
    "501 Method Not Implemented" >!< banner
  )
) exit(0);


# Check possible URLs.
foreach url (make_list("/wsman-anon", "/wsman"))
{
  # Check whether the URL exists.
  w = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(w)) exit(1, "The web server did not answer");
  res = strcat(w[0], w[1], '\r\n', w[2]);
  # If it responds like Openwsman...
  if (
    "405 Method not allowed" >< res ||
    "501 Method Not Implemented" >< res
  )
  {
    # Send an Identify request.
    postdata = string(
      '<?xml version="1.0" encoding="UTF-8" ?>', "\r\n", 
      '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">', "\r\n",
      '  <s:Header/>', "\r\n",
      '  <s:Body>', "\r\n",
      '    <wsmid:Identify/>', "\r\n",
      '  </s:Body>', "\r\n",
      '</s:Envelope>'
    );

    w = http_send_recv3(method: "POST", item: url, port: port,
      content_type:"application/soap+xml;charset=UTF-8",
      data: postdata);
    if (isnull(w)) exit(1, "The web server did not answer");
    res = strcat(w[0], w[1], '\r\n', w[2]);
    # If...
    if (
      # it looks like we need authentication from a known wsman server or...
      'realm="OPENWSMAN"' >< res ||
      # we get an Identify response
      "<wsmid:IdentifyResponse>" >< res
    )
    {
      # Extract info about the server, if possible.
      info = "";
      vendor = "";
      version = "";

      if ("<wsmid:IdentifyResponse>" >< res)
      {
        if ("wsmid:ProductVendor>" >< res)
          vendor = strstr(res, "wsmid:ProductVendor>") - "wsmid:ProductVendor>";
          if (stridx(vendor, "</wsmid:ProductVendor>") > 0)
          {
            vendor = vendor - strstr(vendor, "</wsmid:ProductVendor>");
            info += '  Product Vendor  : ' + vendor + '\n';
          }
          else vendor = "";

        if ("wsmid:ProductVersion>" >< res)
          version = strstr(res, "wsmid:ProductVersion>") - "wsmid:ProductVersion>";
          if (stridx(version, "</wsmid:ProductVersion>") > 0)
          {
            version = version - strstr(version, "</wsmid:ProductVersion>");
            info += '  Product Version : ' + version + '\n';
          }
          else version = "";
      }

      # Record info about it in the KB and report it.
      kb_key = "Services/www/"+port+"/wsman";

      set_kb_item(name:kb_key, value:TRUE);
      if (vendor) set_kb_item(name:kb_key+"/vendor", value:vendor);
      if (version) set_kb_item(name:kb_key+"/version", value:version);

      if (report_verbosity && info)
      {
        report = string(
          "\n",
          "Here is some information about the WS-Management Server :\n",
          "\n",
          info
        );
        security_note(port:port, extra:report);
      }
      else security_note(port);

      exit(0);
    }
  }
}
