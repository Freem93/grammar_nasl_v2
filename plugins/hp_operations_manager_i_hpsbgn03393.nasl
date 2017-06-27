#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85626);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/08/27 04:39:04 $");

  script_cve_id("CVE-2015-2137");
  script_bugtraq_id(76360);
  script_osvdb_id(126139);
  script_xref(name:"HP", value:"HPSBGN03393");
  script_xref(name:"IAVB", value:"2015-B-0104");
  script_xref(name:"HP", value:"SSRT102189");
  script_xref(name:"HP", value:"emr_na-c04762687");

  script_name(english:"HP Operations Manager i (OMi) Unspecified RCE");
  script_summary(english:"Checks for the patch.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an unspecified remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP Operations Manager i (OMi) installed on the remote
host is missing a security patch that fixes an unspecified remote code
execution vulnerability.");
  # https://h20564.www2.hpe.com/portal/site/hpsc/public/kb/docDisplay?docId=emr_na-c04762687
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59999363");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/08/12");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/25");
  
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:hp:operations_manager_i");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("hp_operations_manager_i_installed.nbin");
  script_require_keys("installed_sw/HP Operations Manager i");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("bsal.inc");
include("byte_func.inc");
include("zip.inc");
include("obj.inc");
include("install_func.inc");

global_var appname;
appname = "HP Operations Manager i";

function is_patched(version, patch, path)
{
  local_var item, ip_level, ip_fix, war_path, war_file, share, war_ver,
            manifest_contents, war_fix, hotfix, port, login, fh, rc, pass,
            domain;

  if(version =~ "^0?9\.22$" || version =~ "0?9\.23$")
    return "9.24 with patch";

  ip_fix = 1;
  if(version == "10.00") ip_fix = 2;

  if(isnull(patch))
    return version + ' IP ' + ip_fix;

  item = eregmatch(pattern:"^[0-9.]+ IP ([0-9]+)($|[^0-9])",
                   string:patch);

  if(isnull(item) || isnull(item[1]))
    exit(1, "Unable to parse patch information : '" + patch + "'");

  ip_level = int(item[1]);

  if(ip_fix < ip_level)
    return version + ' IP ' + ip_fix;

  war_path = "wde\webapps\opr-gateway.war";
  if(version =~ "^10\.") war_path = "opr\webapps\opr-gateway.war";

  war_path = hotfix_append_path(path:path, value:war_path);

  war_file = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1",
                          string:war_path);

  share = hotfix_path2share(path:war_path);

  # Connect to the appropriate share.
  port    =  kb_smb_transport();
  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();

  if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }

  fh = CreateFile(
    file:war_file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (isnull(fh))
  {
    NetUseDel();
    exit(1, "Unable to open '" + war_path + "'.");
  }

  manifest_contents = zip_parse(smb:fh, "META-INF/MANIFEST.MF");

  CloseFile(handle:fh);
  NetUseDel();

  if("Implementation-Version" >!< manifest_contents ||
     "Implementation-Build" >!< manifest_contents)
    exit(1, 'Error parsing MANIFEST.MF.');

  item = eregmatch(pattern:"Implementation-Version\s*:\s*([\d.]+)\s*($|[\r\n])",
                   string:manifest_contents);

  if(isnull(item) || isnull(item[1]))
    exit(1, 'Error parsing Implementation-Version from MANIFEST.MF.');

  war_ver = item[1];

  item = eregmatch(pattern:"Implementation-Build\s*:\s*([\d]+)\s*($|[\r\n])",
                   string:manifest_contents);

  if(isnull(item) || isnull(item[1]))
    exit(1, 'Error parsing Implementation-Build from MANIFEST.MF.');

  war_ver += '.' + item[1];

  war_fix = '9.24.164.55810';
  hotfix = 'OMI_00114';
 
  if(version =~ "^0?9\.25$")
  {
    hotfix = 'OMI_00112';
    war_fix = '9.25.311.55760';
  }
  else if(version == "10.00")
  {
    hotfix = 'OMI_00108';
    war_fix = '10.00.326.55620';
  }
  else if(version == "10.01")
  {
    hotfix = 'OMI_00110';
    war_fix = '10.01.112.55594';
  }

  if(ver_compare(ver:war_ver, fix:war_fix, strict:FALSE) == -1)
   return version + " " + ip_level + " hotfix " + hotfix;

  return '';
}

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
version = install['version'];
patch   = install['Patch'];
path    = install['path'];

if(version !~ "^0?9\.2[234]$" && version !~ "^10\.0[01]$")
  audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);

fix = is_patched(version:version, patch:patch, path:path);

if (fix != '')
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version;
    if(!isnull(patch)) report +=
      '\n  Installed patch   : ' + patch;
    report +=
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:kb_smb_transport(), extra:report);
  }
  else security_hole(kb_smb_transport());
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
