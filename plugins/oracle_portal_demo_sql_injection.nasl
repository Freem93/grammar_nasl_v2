#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71048);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/09/24 23:21:18 $");

  script_cve_id("CVE-2013-3831");
  script_bugtraq_id(63043);
  script_osvdb_id(98469);

  script_name(english:"Oracle Portal Demo Organization Chart SQL Injection");
  script_summary(english:"Tries to exploit SQL injection vulnerability");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a demo application under Oracle Portal that
is affected by a SQL injection vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts a version of the Oracle Portal Organization
Chart demo application that does not properly sanitize the
'p_args_values' parameter, making it vulnerable to a SQL injection
attack."
  );
  # http://packetstormsecurity.com/files/123650/Oracle-Portal-Demo-Organization-Chart-PL-SQL-Injection.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c9c4a57");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html"
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac29c174");
  script_set_attribute(attribute:"solution", value:"Apply October 2013 CPU update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_portal_demo_org_chart_detect.nbin");
  script_require_ports("Services/www", 8090);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8090);

demo_org_chart_show = get_kb_item_or_exit("www/oracle_portal/" + port + "/demo_org_chart");
exploit_req = demo_org_chart_show + "?p_arg_names=_max_levels&p_arg_values=1&p_arg_names=_start_with_field&p_arg_values=null&p_arg_names=_start_with_value&p_arg_values=:p_start_with_value%27";

res = http_send_recv3(method:'GET', item:exploit_req, port:port, exit_on_fail:TRUE);

if (
  'Failed to parse query' >< res[2] &&
  '<TITLE>Organization Chart</TITLE>' >< res[2]
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able to demonstrate the vulnerability with the following' +
      '\nGET request:\n' +
      '\n  ' + build_url(port:port, qs:exploit_req);

    item = eregmatch(pattern:'(Failed to parse as[^<]+)<', string:res[2]);
    if (report_verbosity > 1 && !isnull(item))
    {
      report +=
        '\n\nThe following is a snippet of the response : \n\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        chomp(item[1]) + '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30);
    }
    report += '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Oracle Portal Demo Organization Chart");
