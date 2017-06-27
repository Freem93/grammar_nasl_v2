#
# (C) Tenable Network Security, Inc.
#

# Thanks to RFP for his explanations.
#

include("compat.inc");

if (description)
{
 script_id(10410);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2013/12/23 02:27:58 $");

 script_cve_id("CVE-2000-0350");
 script_bugtraq_id(1216);
 script_osvdb_id(312);

 script_name(english:"ISS ICEcap Default Password");
 script_summary(english:"logs into the remote ICEcap subsystem");

 script_set_attribute(attribute:"synopsis", value:"The remote host contains an application with a default password.");
 script_set_attribute(attribute:"description", value:
"The ICEcap package has a default login of 'iceman' with no password. 

An attacker may use this fact to log into the console and/or push false
alerts on port 8082. 

In addition to this, an attacker may inject code in ICEcap v2.0.23 and
below.");
 script_set_attribute(attribute:"see_also", value:"http://www.iss.net/security_center/advice/Support/KB/q000164/default.htm");
 script_set_attribute(attribute:"see_also", value:"http://www.iss.net/security_center/advice/Support/KB/q000166/default.htm");
 script_set_attribute(attribute:"see_also", value:"http://www.iss.net/security_center/advice/Support/KB/q000167/default.htm");
 script_set_attribute(attribute:"solution", value:"Set a strong password on the 'iceman' account.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/09/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/18");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2000-2013 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/ICEcap", 8082);
 exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_service(svc:"ICEcap", default:8082, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

code = http_get_cache(item:"/", port:port, exit_on_fail: 1);
if (code && ereg(string:code, pattern:"^HTTP/[0-9]\.[0-9] 401 .*"))
{
  w = http_send_recv3(method:"GET", item:"/", port:port,
    username: "iceman", password: "%3B7%C6%FE", exit_on_fail: 1);

  if (w[0] =~ "^HTTP/[0-9]\.[0-9] 200 ") security_warning(port);
}

