#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90196);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/10/03 14:18:40 $");

  script_cve_id("CVE-2016-1988", "CVE-2016-1989");
  script_osvdb_id(135773, 135774);
  script_xref(name:"HP",value:"emr_na-c05030906");
  script_xref(name:"HP",value:"HPSBGN03444");
  script_xref(name:"HP",value:"PSRT110043");

  script_name(english:"HP Network Automation 9.22.0x / 10.00.0x < 10.00.02 Multiple RCE");
  script_summary(english:"Checks the version of HP Network Automation.");

  script_set_attribute(attribute:"synopsis",value:
"A web application running on the remote host is affected by multiple
remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The HP Network Automation application running on the remote host is
version 9.22.0x or version 10.00.0x prior to 10.00.02. It is,
therefore, affected by multiple remote code execution vulnerabilities
due to multiple unspecified flaws. A remote attacker can exploit these
issues to execute arbitrary code or to disclose sensitive information
via unspecified vectors.");
  # http://h20565.www2.hpe.com/hpsc/doc/public/display?calledBy=&docId=emr_na-c05030906
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?69bf484f");
  script_set_attribute(attribute:"solution",value:
"For HP Network Automation 10.00.0x, upgrade to version 10.00.02 or
later. For HP Network Automation 9.22.0x, contact the vendor for a
fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/03/03");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/25");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:hp:network_automation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("hp_network_automation_detect.nbin");
  script_require_keys("installed_sw/HP Network Automation");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = "HP Network Automation";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

port    = get_http_port(default:443);
install = get_single_install(app_name:app_name, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];
url     = build_url(port:port,qs:install['path']);

fix = NULL;
display_fix = '';

if (version =~ "^9\.22(\.|$)")
{
  # Remediation is not published, being careful here.
  if (report_paranoia > 1)
  {
    fix = "9.22.03"; # Not official, needed for logic
    display_fix = "See vendor";
  }
  else
    audit(AUDIT_PARANOID);
}
else if (version =~ "^10(\.0+(\.\d+)*)?$")
{
  fix = "10.00.02";
  display_fix = fix;
}

if (isnull(fix))
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0 )
{
  items = make_array("URL", url,
                     "Installed version", version,
                     "Fixed version", display_fix
                    );
  order = make_list("URL", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, version);
