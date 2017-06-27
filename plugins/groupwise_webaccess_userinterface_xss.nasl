#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(60047);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/13 20:37:05 $");

  script_cve_id("CVE-2012-0410");
  script_bugtraq_id(54253);
  script_osvdb_id(83495);

  script_name(english:"Novell GroupWise WebAccess User.interface XSS");
  script_summary(english:"Attempts XSS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The application hosted on the remote web server has a cross-site
scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Novell GroupWise WebAccess hosted on the remote web
server has a cross-site scripting vulnerability.  This
vulnerability is present when files are retrieved by passing a
directory traversal string to the User.interface parameter.  An
attacker could exploit this by tricking a user into making a
maliciously crafted request, resulting in the execution of arbitrary
script code."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7000708");
  script_set_attribute(attribute:"solution", value:"Upgrade to GroupWise 8.0 Support Pack 3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise_webaccess");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80);
xss = '"><img/src="' + unixtime() + '"/onerror=javascript:alert(/' + SCRIPT_NAME + '/")>';
expected_output = '"' + xss + '" TITLE="Novell GroupWise">';

foreach dir (make_list('/gw', '/servlet'))
{
  url = dir + '/webacc?User.interface=/../webacc/hdml&User.id=' + xss;
  res = http_send_recv3(port:port, method:'POST', item:url, data:'', exit_on_fail:TRUE);
  
  if (expected_output >!< res[2])
    continue;
  
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    snippet = extract_pattern_from_resp(string:res[2], pattern:'ST:' + expected_output);
  
    report =
      '\nNessus detected this issue by making the following request :\n\n' +
      chomp(http_last_sent_request()) + '\n' +
      '\nWhich resulted in the following response (excerpt) :\n\n' +
      chomp(snippet) + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
  # never reached
}

exit(0, 'The host is not affected on port ' + port + '.');

