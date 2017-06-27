#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64703);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/02/20 14:24:08 $");

  script_cve_id("CVE-2012-4616");
  script_bugtraq_id(57046);
  script_osvdb_id(88724);

  script_name(english:"EMC Data Protection Advisor Web UI Directory Traversal");
  script_summary(english:"Checks build date DPA_GUI.jar");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server is affected by a directory traversal
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its build date, the EMC Data Protection Advisor Web UI on
the remote host is affected by a directory traversal vulnerability that
may allow a remote, unauthenticated attacker to copy and read files from
the affected system."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Dec/att-124/ESA-2012-060.txt");
  script_set_attribute(attribute:"solution", value:"Apply patch DPA-21068.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:data_protection_advisor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("emc_dpa_web_detect.nasl");
  script_require_keys("www/emc_dpa");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 443, 9002);
  exit(0);
}

include("audit.inc");
include('global_settings.inc');
include("smb_func.inc");
include("bsal.inc");
include('misc_func.inc');
include('byte_func.inc');
include("http.inc");
include("webapp_func.inc");
include("zip.inc");

port = get_http_port(default:9002);

appname = "EMC Data Protection Advisor Web UI";

install = get_install_from_kb(appname:'emc_dpa', port:port, exit_on_fail:TRUE);
version = install['ver'];

http_set_max_req_sz(10000000);
res = http_send_recv3(method:"GET",
                      item:'/DPA_GUI.jar',
                      port:port,
                      exit_on_fail:TRUE);

if (res[0] !~'^HTTP/[0-9.]+ +200' || isnull(res[2])) exit(1, 'Failed to get contents of DPA_GUI.jar.');

jar = res[2];
manifest = zip_parse(blob:jar, "META-INF/MANIFEST.MF");
if (isnull(manifest)) exit(1, "Failed to extract contents of DPA_GUI.jar.");

if (version == UNKNOWN_VER)
{
  item = eregmatch(pattern: "Implementation-Version: ([0-9.]+)", string:manifest);
  if (!isnull(item)) version = item[1];
}

if (version == UNKNOWN_VER) exit(1, 'Unable to determine the products version.');

item = eregmatch(pattern: "Built-Date: ([0-9]+) (\d{2}:\d{2})", string:manifest);
if (isnull(item)) exit(1, 'Unable to parse build date from \'META-INF/MANIFEST.MF\'.');

build_src = item[0];
build_date = item[1];
build_time = item[2];

int_build_date = int(build_date);
# remove seperator from build time
int_build_time = int(build_time - ':');

fix_date = 0;
fix_time = 0;
fix = '';
fixed_build = '';

if (version =~ "^5\.8\.")
{
  fix_date = 20121128;
  fix_time = 2314;
  fix = '5.8.4 with patch DPA-21068';
  fixed_build = '20121128 23:14';
}
else if (version =~ "^5\.7\.")
{
  fix_date = 20121128;
  fix_time = 2353;
  fix = '5.7.1 with patch DPA-21068';
  fixed_build = '20121128 23:53';
}
else if (version =~ "^5\.6\.")
{
  fix_date = 20121129;
  fix_time = 14;
  fix = '5.6.1 with patch DPA-21068';
  fixed_build = '20121129 00:14';
}
else
  audit(AUDIT_INST_VER_NOT_VULN, appname, version);

if (
  int_build_date < fix_date ||
  (int_build_date == fix_date && int_build_time < fix_time)
)
{
  if (report_verbosity > 0)
  {
    report = '';
    if (report_verbosity > 1)
    {
      report += '\n  DPA_GUI.jar build date source : "' + build_src + '"' +
                '\n  DPA_GUI.jar build date        : ' + build_date + ' ' +
                build_time +
                '\n  Fixed DPA_GUI.jar build date  : ' + fixed_build +
                '\n';
    }
    report += '\n  Current EMC DPA version       : ' + version +
              '\n  Fixed EMC DPA version         : ' + fix + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, version + ' (Built ' + build_date + ' ' + build_time + ')');
