#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83489);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2015-2121");
  script_bugtraq_id(74583);
  script_osvdb_id(121901);
  script_xref(name:"HP", value:"HPSBGN03328");
  script_xref(name:"IAVB", value:"2015-B-0062");
  script_xref(name:"HP", value:"SSRT101932");
  script_xref(name:"HP", value:"emr_na-c04657310");

  script_name(english:"Network Virtualization for HP LoadRunner Information Disclosure");
  script_summary(english:"Checks the version of HP LoadRunner.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of HP LoadRunner installed that
is 11.52.x and a version of HP Network Virtualization installed that
is prior to 8.61 patch 3. It is, therefore, affected by an information
disclosure vulnerability due to a failure in HttpServlet and
NetworkEditorController to properly sanitize filenames. A remote
attacker can exploit this, via a specially crafted request, to
disclose the contents of arbitrary files.");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04657310
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3129c180");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP Network Virtualization 8.61 Patch 3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:network_virtualization");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:loadrunner");
  
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_loadrunner_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/HP LoadRunner");
  script_require_ports(139, 445);

  exit(0);
}

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('misc_func.inc');
include("install_func.inc");

app_name = "HP LoadRunner";
# Only 1 install of the server is possible.
install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);

version = install['version'];
path = install['path'];

# Determine cutoff if affected branch.
# 11.52.0 is 11.52.1323.0 or 11.52.1517.0
if (version !~ "^11\.52($|[^0-9])")
  audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Shunra\Bootstrapper\InstalledPath";
path = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);

if (empty_or_null(path)) audit(AUDIT_NOT_INST, "Network Virtualization for HP LoadRunner");
dll = hotfix_append_path(path:path, value:"lib\shunra\snv\ShunraAPIRest.dll");
ver = hotfix_get_fversion(path:dll);
err_res = hotfix_handle_error(
  error_code   : ver['error'],
  file         : dll,
  appname      : "Network Virtualization for HP LoadRunner",
  exit_on_fail : FALSE
);
if (err_res)
  audit(AUDIT_UNINST, "Network Virtualization for HP LoadRunner");

dll_ver = join(sep:'.', ver['value']);
if (empty_or_null(dll_ver)) audit(AUDIT_VER_FAIL, dll);

if (dll_ver =~ '^8\\.61\\.' && ver_compare(ver:dll_ver, fix:"8.61.0.160", strict:FALSE) < 0)
{
  port = kb_smb_transport();
  if (report_verbosity > 0)
  {
    report +=
      '\n  Path                  : ' + path +
      '\n  DLL                   : ' + dll +
      '\n  Installed DLL version : ' + dll_ver +
      '\n  Fixed DLL version     : 8.61.0.160\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, "Network Virtualization for HP LoadRunner", dll_ver, path);
