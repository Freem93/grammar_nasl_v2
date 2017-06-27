#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14626);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/10/07 13:30:47 $");

  script_cve_id("CVE-2002-0504");
  script_bugtraq_id(4372);
  script_osvdb_id(9256, 9257);
  script_xref(name:"EDB-ID", value:"21355");

  script_name(english:"Citrix NFuse Launch Scripts 'NFuse_Application' Parameter XSS");
  script_summary(english:"Test Citrix NFuse_Application parameter XSS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote version of Citrix NFuse contains a flaw that allows a
remote cross-site scripting attack. An attacker can exploit this issue
to execute arbitrary HTML or script code in a user's browser within
the security context of the affected site.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Mar/398");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/02");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/03/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:nfuse");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP");

  exit(0);
}

# start the test

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, asp:TRUE);

if(get_kb_item("www/"+ port + "/generic_xss")) exit(0);

# Ensure we only flag an IIS server.
banner = get_http_banner(port:port, exit_on_fail:TRUE);
if ("IIS/" >!< banner && "Apache" >!< banner) audit(AUDIT_WRONG_WEB_SERVER, port, "Microsoft IIS or Apache");

scripts = make_list("/launch.jsp", "/launch.asp");
xss_tag = SCRIPT_NAME - ".nasl" + "-" + unixtime();
str = "?NFuse_Application=>alert('"+xss_tag+"');</script>";

foreach script (scripts)
{
  r = http_send_recv3(
    method  : "GET",
    port    : port,
    item    : script + str,
    exit_on_fail : TRUE
  );

  xss_str = "alert('"+xss_tag+"');</script>";

  if(r[0] =~ "200" && xss_str >< r[2] && ereg(pattern:"nfuse", string:r[2], icase:TRUE, multiline:TRUE))
  {
    output = extract_pattern_from_resp(pattern:"ST:"+xss_str, string: r[2]);
    if (empty_or_null(output)) output = r[2];

    security_report_v4(
      port       : port,
      severity   : SECURITY_WARNING,
      generic    : TRUE,
      xss        : TRUE,  # XSS KB key
      request    : make_list(build_url(qs:script+str, port:port)),
      output     : output
    );
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "Citrix NFuse", build_url(qs:"/",port:port));
