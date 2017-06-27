#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94900);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/01/16 15:05:10 $");

  script_osvdb_id(146713);

  script_name(english:"Sophos Web Protection Appliance Open Redirect Vulnerability");
  script_summary(english:"Attempts to trigger redirect.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by an
open redirect vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Sophos Web Protection application running on the remote host is
affected by an open redirect vulnerability in the FTP over HTTP page
due to improper validation of user-supplied input. An unauthenticated,
remote attacker can exploit this, by convincing a user to click a
specially crafted link, to redirect a user to a malicious website.

Note that the application is reportedly affected by additional
vulnerabilities; however, this plugin has not tested for them.");
  script_set_attribute(attribute:"see_also", value:"http://swa.sophos.com/rn/swa/concepts/ReleaseNotes_4.3.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sophos Web Protection Appliance version 4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sophos:web_appliance");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:sophos:sophos_web_protection");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("sophos_web_protection_detect.nasl");
  script_require_keys("installed_sw/sophos_web_protection");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

get_install_count(app_name:'sophos_web_protection', exit_if_zero:TRUE);
port = get_http_port(default:443);
install = get_single_install(app_name:'sophos_web_protection', port:port);

url = '/end-user/ftp_redirect.php?r=1&host=test&msg=test&ip=test&s=www.tenable.com';
resp = http_send_recv3(
  port:port,
  method:'GET',
  item:url);
if (isnull(resp) || "200" >!< resp[0]) audit(AUDIT_LISTEN_NOT_VULN, "Sophos Web Protection", port);

# The page should just be <script> tags that force a redirect
pattern = "^<script>window.location.href = 'http://www\.tenable\.com/end-user/ftp_redirect\.php\?h=&msg=test&STYLE=[a-f0-9]+'</script>$";
match = eregmatch(pattern:pattern, string:resp[2]);
if (isnull(match)) audit(AUDIT_LISTEN_NOT_VULN, "Sophos Web Protection", port);

report = 'Nessus was able to exploit an open redirect vulnerability by visiting :\n\n' +
         'https://' + get_host_ip() + url + '\n';
security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
exit(0);
