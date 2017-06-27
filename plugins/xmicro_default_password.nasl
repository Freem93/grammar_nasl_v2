#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12203);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/11/01 19:59:57 $");

  script_cve_id("CVE-2004-1920");
  script_bugtraq_id(10095);
  script_osvdb_id(5231);

  script_name(english:"Web Application Default Username ('super'/'1502') / Password ('super'/'1502')");
  script_summary(english:"Attempts to login to a default account");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a default username and password set for a
management console.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to login to the web application on the remote host 
using the username 'super' and password 'super' or username '1502' and 
password '1502'. 

Note: X-Micro routers are known to use these default credentials.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Apr/214");
  script_set_attribute(attribute:"solution", value:
"If this is an X-Micro router, upgrade to the latest version of the 
firmware. Otherwise, contact the product's vendor for guidance to
change the credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

i = 0;
username[i++] = "super";
username[i++] = "1502";

port = get_http_port(default:80);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

r = http_send_recv3(method:"GET", item:"/", port:port, username:"nessus", password:"n3ssus", exit_on_fail:TRUE);
if (r[0] !~ "^HTTP.* 403 ") exit(0, "The initial page for the web server listening on port "+port+" does not require authentication.");

# Unless we're paranoid, make sure a random password doesn't work.
if (report_paranoia < 2)
{
  r = http_send_recv3(method:"GET", item:"/", port:port, username:"nessus", password:rand_str(length:8), exit_on_fail:TRUE);
  if (r[0] =~ "^HTTP/.* 200 ") exit(0, "The web server listening on port "+port+" seems to accept a random password.");
}

foreach u (username)
{
  r = http_send_recv3(method:"GET", item:"/", port:port, username:u, password:u, exit_on_fail:TRUE);

  if (r[0] =~ "^HTTP.* 200 ")
  {
    if (report_verbosity > 0)
    {
      report =
        '\n' +
        'Nessus was able to exploit the issue with the following credentials :\n' +
        u + ":" + u + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
exit(0, "The web server listening on port "+port+" is not affected.");
