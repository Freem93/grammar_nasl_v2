#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11504);
 script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");
 script_cve_id("CVE-2002-1629");
 script_bugtraq_id(7203);
 script_osvdb_id(19107);

 script_name(english:"MultiTech Proxy Server Default Null Password");
 script_summary(english:"Attempts to log into the remote web server");

 script_set_attribute(attribute:"synopsis", value:"The remote Proxy server uses a default password.");
 script_set_attribute(attribute:"description", value:
"The remote MultiTech Proxy Server has no password set for the
'supervisor' account.

An attacker may log in the remote host and reconfigure it
easily.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Dec/106");
 script_set_attribute(attribute:"solution", value:"Set a strong password for the 'supervisor' account.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/12/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/30");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl", "webmirror.nasl");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

w = http_send_recv3(method:"GET", item:"/std.html", port:port, username: "", password: "", exit_on_fail:TRUE);
if (w[0] =~ "^HTTP/[0-9]\.[0-9] 40[13] ")
 {
  w = http_send_recv3(method:"GET", item:"/std.html", port:port,
    username: "supervisor", password: "", exit_on_fail:TRUE);
  if (w[0] =~ "^HTTP/[0-9]\.[0-9] 200 ")
  {
   security_hole(port);
   exit(0);
  }
 }
exit(0, "The web server listening on port "+port+" is not affected.");
