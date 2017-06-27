#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62974);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/06 20:34:49 $");

  script_cve_id("CVE-2012-4955");
  script_bugtraq_id(56518);
  script_osvdb_id(87405);
  script_xref(name:"CERT", value:"558132");

  script_name(english:"Dell OpenManage Server Administrator omalogin.html DOM-based XSS");
  script_summary(english:"Requests PoC URL");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application hosted on the remote web server has a cross-site
scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Dell OpenManage Server Administrator hosted on the
remote web server has a cross-site scripting vulnerability.  Making a
specially crafted request for omalogin.html can result in client-side
script injection.  An attacker could exploit this by tricking a user
into requesting a maliciously crafted URL. 

A similar vulnerability exists in omatasks.html, but Nessus has not
tested that attack vector."
  );
  # http://www.dell.com/support/drivers/us/en/19/DriverDetails/Product/poweredge-r710?driverId=JJMWP&osCode=WNET&fileId=3082295338
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c34c744f");
  # http://www.dell.com/support/drivers/us/en/19/DriverDetails/Product/poweredge-r710?driverId=PCXMR&osCode=WNET&fileId=3082295344
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?578ea62e");
  # http://www.dell.com/support/drivers/us/en/19/DriverDetails/Product/poweredge-r710?driverId=5JDN0&osCode=WNET&fileId=3082293694
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f5bf40c");
  script_set_attribute(
    attribute:"solution",
    value:
"For Windows systems, upgrade to version 6.5, 7.0, or 7.1 (if necessary)
and apply the appropriate patch referenced in US-CERT VU#558132. 

For Linux systems, there is no known solution at this time."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:openmanage_server_administrator");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("dell_openmanage.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/dell_omsa");
  script_require_ports("Services/www", 1311);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:1311, embedded:TRUE);
install = get_install_from_kb(appname:'dell_omsa', port:port, exit_on_fail:TRUE);
base_url = build_url(qs:install['dir'], port:port);

poc_url = install['dir'] + '/omalogin.html?msgStatus="><script>alert(/' + SCRIPT_NAME + unixtime() + '/)</script>';
res = http_send_recv3(method:'GET', item:poc_url, port:port, exit_on_fail:TRUE);

hdrs = parse_http_headers(status_line:res[0], headers:res[1]);
if (hdrs['$code'] == 200)                             # does it return a 200 status?
{
  if ('function QueryString_Parse' >< res[2] ||        # does it contain the vulnerable JS code?
      'function QueryString' >< res[2] ||
      'QueryString("msgStatus")' >< res[2])
  {
    if ('function removeSpChars' >!< res[2] ||           # it doesn't contain the remediation code?
        'removeSpChars(value)' >!< res[2])
    {
      report = get_vuln_report(port:port, items:poc_url);
      security_report_v4(extra:report, port:port, severity:SECURITY_WARNING, xss:TRUE);
    }
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Dell OpenManage Server Administrator', base_url);
