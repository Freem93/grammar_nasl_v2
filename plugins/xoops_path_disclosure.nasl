#
# (C) Tenable Network Security, Inc.
#

# Ref :
#  Date: 20 Mar 2003 19:58:55 -0000
#  From: "Gregory" Le Bras <gregory.lebras@security-corporation.com>
#  To: bugtraq@securityfocus.com
#  Subject: [SCSA-011] Path Disclosure Vulnerability in XOOPS
#
# This check will incidentally cover other flaws.


include("compat.inc");

if (description)
{
 script_id(11439);
 script_version("$Revision: 1.23 $");
 script_cvs_date("$Date: 2016/05/26 16:22:51 $");
 script_cve_id("CVE-2002-0216", "CVE-2002-0217", "CVE-2002-1802");
 script_bugtraq_id(3977, 3978, 3981, 5785, 6344, 6393);
 script_osvdb_id(9287, 9288, 9392, 59314);

 script_name(english:"XOOPS 1.0 RC1 Multiple Vulnerabilities");
 script_summary(english:"Checks for XOOPS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of XOOPS installed on the remote host is affected by SQL
injection, cross-site scripting, and information disclosure." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=104820295115420&w=2");
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=101232435812837&w=2" );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=101232476214247&w=2" );
 script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/01/29");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/22");

script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("xoops_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/xoops");
 exit(0);
}

# The script code starts here
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php: 1);


# Test an install.
z = get_install_from_kb(appname: "xoops", port: port, exit_on_fail: 1);

d = z['dir'];

u = strcat(d, "/index.php?xoopsOption=nessus");
w = http_send_recv3(method:"GET", item: u, port:port, exit_on_fail: 1);
if (egrep(pattern:"Fatal error.* in <b>/", string: w[2]))
{
  if (report_verbosity <= 0)
    security_hole(port);
  else
  {
    e = get_vuln_report(items: u, port: port);
    security_hole(port: port, extra: e);
  }
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  exit(0);
}
