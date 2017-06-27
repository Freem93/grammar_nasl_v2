#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38208);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/01/30 19:28:01 $");

  script_cve_id("CVE-2008-6682");
  script_bugtraq_id(34686);
  script_osvdb_id(54122);
  script_xref(name:"Secunia", value:"32497");

  script_name(english:"Apache Struts 2 s:a / s:url Tag href Element XSS");
  script_summary(english:"Attempts a non-persistent XSS attack.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by
multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The web application on the remote host is affected by a cross-site
scripting vulnerability due to a vulnerable version of Apache Struts 2
that fails to properly encode the parameters in the 's:a' and 's:url'
tags.

A remote attacker can exploit this by tricking a user into requesting
a page with arbitrary script code injected. This could have
consequences such as stolen authentication credentials.");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/WW-2414");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/WW-2427");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/s2-002.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Struts version 2.1.1 / 2.0.11.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("webmirror.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);

xss_params = '"><script>alert(\'' +SCRIPT_NAME+ '-' + unixtime() + '\')</script>';

# Escapes parens so they're interpreted as literals in a regex
escaped_params = str_replace(string:xss_params, find:"(", replace:"\(");
escaped_params = str_replace(string:escaped_params, find:")", replace:"\)");

cgis = get_kb_list('www/' + port + '/cgi');

urls = make_list();
# To identify actions that we can test the exploit on we will look
# for files with the .action / .jsp / .do suffix from the KB.
if (!isnull(cgis))
{
  foreach cgi (cgis)
  {
    match = eregmatch(pattern:"((^.*)(/.+\.act(ion)?)($|\?|;))", string:cgi);
    if (match)
    {
      urls = make_list(urls, match[0]);
      if (!thorough_tests) break;
    }
    match2 = eregmatch(pattern:"(^.*)(/.+\.jsp)$", string:cgi);
    if (!isnull(match2))
    {
      urls = make_list(urls, match2[0]);
      if (!thorough_tests) break;
    }
    match3 = eregmatch(pattern:"(^.*)(/.+\.do)$", string:cgi);
    if (!isnull(match3))
    {
      urls = make_list(urls, match3[0]);
      if (!thorough_tests) break;
    }
  }
}
if (thorough_tests)
{
  cgi2 = get_kb_list('www/' + port + '/content/extensions/act*');
  if (!isnull(cgi2)) urls = make_list(urls, cgi2);

  cgi3 = get_kb_list('www/' + port + '/content/extensions/jsp');
  if (!isnull(cgi3)) urls = make_list(urls, cgi3);

  cgi4 = get_kb_list('www/' + port + '/content/extensions/do');
  if (!isnull(cgi4)) urls = make_list(urls, cgi4);
}

if (max_index(urls) == 0)
  audit(AUDIT_WEB_FILES_NOT, "Struts 2 .action / .do / .jsp", port);

urls = list_uniq(urls);

exploited = 0;

foreach url (urls)
{
  if (test_cgi_xss(
    port     : port,
    dirs     : make_list(''),
    cgi      : url,
    qs       : xss_params,
    pass_re  : '<a href="[^"]+' + escaped_params,
    ctrl_re  : escaped_params
  )) exploited++;
}

if (!exploited) exit(0, 'No vulnerable applications were detected on the web server listening on port '+port+'.');
