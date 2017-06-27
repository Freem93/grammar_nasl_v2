#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33220);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2008-2640");
  script_bugtraq_id(29778);
  script_osvdb_id(46301);
  script_xref(name:"Secunia", value:"30746");

  script_name(english:"Adobe Flex 3 History Management historyFrame.html XSS");
  script_summary(english:"Looks for vulnerable versions of historyFrame.html");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains HTML documents that are affected by a
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host contains one or more HTML documents associated with
Adobe Flex 3's History Management Feature and affected by a DOM-based
cross-site scripting vulnerability.  Due to its failure to sanitize
user input, an attacker may be able to leverage this issue to inject
arbitrary HTML and script code into a user's browser to be executed
within the security context of the affected site, possibly by using
JavaScript code flow manipulation techniques." );
 script_set_attribute(attribute:"see_also", value:"http://blog.watchfire.com/wfblog/2008/06/javascript-code.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb08-14.html" );
 script_set_attribute(attribute:"solution", value:
"Replace the affected file(s) with an instance of 'historyFrame.html'
from the Flex 3.0.2 update as discussed in the vendor advisory above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/06/18");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/06/17");
 script_cvs_date("$Date: 2013/03/26 21:41:01 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:adobe:flex_builder");
script_set_attribute(attribute:"cpe",value:"cpe:/a:adobe:flex_sdk");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Loop through directories.
info = "";

foreach dir (cgi_dirs())
{
  # Retrieve the affected file.
  url = string(dir, "/historyFrame.html");

  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # Look for a vulnerable version.
  if (
    "document.write(url);" >< res &&
    "function processUrl()" >< res &&
    "if (!parent._ie_firstload)" >< res &&
    "Hidden frame for Browser History support." >< res
  )
  {
    info += '  ' + url + '\n';
    if (!thorough_tests) break;
  }
}


# Report if a problem was found.
if (info)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Nessus discovered the following vulnerable instance(s) of the file on\n",
      "the remote host :\n",
      "\n",
      info
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
