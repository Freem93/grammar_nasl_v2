#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73738);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/08 22:17:48 $");

  script_cve_id("CVE-2014-0465", "CVE-2014-2425", "CVE-2014-2426");
  script_bugtraq_id(66849, 66874, 66878);
  script_osvdb_id(105824, 105825, 105826);

  script_name(english:"Oracle OpenSSO Multiple Vulnerabilities (April 2014 CPU)");
  script_summary(english:"Checks for patch");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple, unspecified vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle OpenSSO install is missing a vendor-supplied update.
It is, therefore, affected by multiple, unspecified vulnerabilities.");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef1fc2a6");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2014 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("oracle_opensso_detect.nbin");
  script_require_keys("www/oracle_opensso");
  script_require_ports("Services/www", 7001, 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "Oracle OpenSSO";

port = get_http_port(default:7001);

install = get_install_from_kb(appname:"oracle_opensso", port:port, exit_on_fail:TRUE);

dir = install['dir'];
version = install['ver'];

orig_ver_str = version;

install_url = build_url(port:port, qs:dir);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Oracle OpenSSO", install_url);

item = eregmatch(pattern:"^([0-9.]+)[^0-9.]", string:version);
if (isnull(item)) exit(1, "Unable to parse version string for server on port " + port + ".");

main_ver = item[1];

patch_num = 0;
item = eregmatch(pattern:" [pP]atch[ \t]*([0-9]+)($|[^0-9])", string:version);
if (!isnull(item)) patch_num = int(item[1]);

update_num = 0;
item = eregmatch(pattern:" [uU]pdate[ \t]*([0-9]+)($|[^0-9])", string:version);
if (!isnull(item)) update_num = int(item[1]);

report = '';

# 8.0 Update 2 Patch 5 is listed as affected
# convert to something we can use in ver_compare
if (main_ver =~ "^8($|\.0+$)" && patch_num == 5 && update_num == 2)
{
  res = http_send_recv3(item:dir + '/webcli',
                        port:port,
                        method:'GET',
                        fetch404: TRUE,
                        exit_on_fail:TRUE);

  # patch removes webcli servlet
  if (
    "amadm --version, -V" >< res[2] && "Usage:" >< res[2] &&
    "Print version of this tool." >< res[2]
  )
  {
    report = '\n  Installed version : ' + orig_ver_str +
             '\n  Fixed version     : 8.0 Update 2 Patch 5 with patch' +
             '\n  Required patch    : 18435359\n';
  }
}

if (report == '') audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url);

if (report_verbosity > 0) security_warning(extra:report, port:port);
else security_warning(port);
