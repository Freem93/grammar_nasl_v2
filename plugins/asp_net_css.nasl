#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added links to the Bugtraq message archive and Microsoft Knowledgebase
#

include("compat.inc");

if(description)
{
  script_id(10844);
  script_version ("$Revision: 1.33 $");
  script_cvs_date("$Date: 2015/10/16 14:54:37 $");

  script_cve_id("CVE-2003-0223");
  script_bugtraq_id(7731);
  script_osvdb_id(7737);

  script_name(english:"Microsoft IIS ASP Redirection Function XSS");
  script_summary(english:"Tests for ASP.NET XSS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a cross-site scripting vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host contains an ASP.NET installation that is affected by a
cross-site scripting vulnerability. An attacker can exploit this issue
to execute arbitrary HTML or script code in a user's browser within
the security context of the affected site.");
  script_set_attribute(attribute:"see_also", value:"http://msdn.microsoft.com/en-us/library/ms972823.aspx");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/?kbid=811114");
  script_set_attribute(attribute:"solution", value:
"Microsoft released a patch for this issue. Refer to the supplied link.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/02/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:internet_information_server");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2002-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP", "www/iis");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, asp:TRUE);

if(get_kb_item("www/"+ port + "/generic_xss")) exit(0);

# Ensure we only flag an IIS server.
banner = get_http_banner(port:port, exit_on_fail:TRUE);
if ("IIS/" >!< banner) audit(AUDIT_WRONG_WEB_SERVER, port, "Microsoft IIS");

xss_tag = SCRIPT_NAME - ".nasl" + "-" + unixtime();
str = "/~/<script>alert('"+xss_tag+"')</script>.aspx?aspxerrorpath=null";
r = http_send_recv3(port: port, method: 'GET', item: str, exit_on_fail:TRUE);

lookfor = "<script>alert('"+xss_tag+"')</script>";
if (lookfor >< r[2] && r[0] =~ "301|302")
{
  output = extract_pattern_from_resp(pattern:"ST:"+lookfor, string: r[2]);
  if (empty_or_null(output)) output = r[2];
  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    generic    : TRUE,
    xss        : TRUE,  # XSS KB key
    request    : make_list(build_url(qs:str, port:port)),
    output     : output
  );
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Microsoft IIS", port);
