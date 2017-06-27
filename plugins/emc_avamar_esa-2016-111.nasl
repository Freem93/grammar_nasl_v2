#TRUSTED 797e57f7dbcf101a7dbdfe4bd72a2c18d3f59a1545d16cd9cba69ab796a12649a9a8970cb5e8b3a3d1b6268e1ba490b10dffa0eb08f0139a52b5e1f4ca73b6ad4256fbaadc04ba88c069195027e5383faaca9c1aefcc797e4c64c968f013b8cac2a81524512e8ed0a30593a478e9cb6a3620043c58c6f0aaaf4629ec5f917f41fd2d9f110f8be5123f033a7aa7c8cfd4a789fe66e2d85242f34e49a7fddff4e944df647ad0dc90b7a91f2c870e01592a5f93b62bbd007013c3f67dc77538aa775c2f248a99bc7fd060e0f0882fe7f7fe44cffbb7f12f7a64dcde1d9e8586fb751af3068c3cbbad3036b3b65fe018db699ddecb7d5e9faa74e36b75d784dac2f6f18fbc0f1e1aec2675f4a7f4e147a93f737f34467372faf6e8b9b88ee1ae12c0c5beceb91e9f654049e67ab086d82dc35e9f281c96f060620ce413129fc28045b4afe17aa2454fa858b038c9411a6357f9ed91358e7770d2851718bd525ee380408db3a2d1bfcaf3df86017264dca4686381bca5f793c1e6d11a41ead928b2c0b87c1513b1bbe135006287fe8753cd9c93817425a61524fdb3d226bb050c5a17f429c292578aa9f6c29688a6d86a8bddc09abbf166a34d8ae42076a5cc966a5de67e960fd4507451196a23c42fcfadcc4cbb3e5d28d18f8a5a7c90e5d3dc86da12ccfdde54982a9525f72b1cbcd3dcfe58e662d9b33da7417c67bcc05c43f77e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95921);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/02/02");

  script_cve_id("CVE-2016-0909");
  script_bugtraq_id(93788);
  script_osvdb_id(146084);

  script_name(english:"EMC Avamar ADS / AVE < 7.3.0 Hotfix 263301 PostgreSQL Command Local Privilege Escalation (ESA-2016-111)");
  script_summary(english:"Checks the version and configuration of EMC Avamar.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a backup solution that is affected by a
local privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The EMC Avamar Data Store (ADS) or Avamar Virtual Edition (AVE)
running on the remote host is a version prior to 7.3.0 Hotfix 263301,
or the configuration is not patched. It is, therefore, affected by a
local privilege escalation vulnerability that allows a local attacker
to execute arbitrary PostgreSQL commands and thereby gain elevated
privileged.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2016/Oct/att-45/ESA-2016-111.txt");
  script_set_attribute(attribute:"see_also", value:"https://support.emc.com/kb/486276");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC Avamar ADS / AVE version 7.3.0 Hotfix 263301 and apply
the configuration changes documented in KB486276.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:avamar");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:avamar_data_store");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:avamar_server_virtual_edition");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("emc_avamar_server_detect.nbin", "emc_avamar_server_installed_nix.nbin");
  script_require_keys("installed_sw/EMC Avamar");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("ssh_func.inc");
include("hostlevel_funcs.inc");
include("telnet_func.inc");
include("http.inc");
include("misc_func.inc");

app = "EMC Avamar";
get_install_count(app_name:app, exit_if_zero:TRUE);

install = make_array();
port = 0;

if (get_kb_item("installed_sw/EMC Avamar/local"))
{
  install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
}
else
{
  port = get_http_port(default:443);
  install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
}

version    = install['version'];
version_ui = install['display_version'];
hotfixes   = install['Hotfixes'];

fix_ver = '7.3.0.233';
fix_hf  = '263301';

vuln         = FALSE; 
config_check = FALSE;

report_fix    = NULL;
insecure_file = NULL;

if (ver_compare(ver:version, fix:fix_ver, strict:FALSE) < 0)
  vuln = TRUE;

# Remote checks cannot check the configuration or hotfix reliably
if (!vuln && port != 0)
  exit(0, "The "+app+" "+version_ui+" install listening on port "+port+" may be affected but Nessus was unable to test for the issue. Please provide valid credentials to test for the issue.");

# Check for hotfixes
if (ver_compare(ver:version, fix:fix_ver, strict:FALSE) == 0)
{
  if (empty_or_null(hotfixes))
    vuln = TRUE;
  else
  {
    hotfixes = split(hotfixes, sep:";", keep:FALSE);
    foreach hotfix (hotfixes)
    {
      if (fix_hf == hotfix)
      {
        config_check = TRUE;
        version_ui += " HF" + fix_hf;
      }
    }
    if (!config_check) vuln = TRUE;
  } 
}
# For versions later than 7.3.0.233 HF263301 we still need to check the configs
else if (ver_compare(ver:version, fix:fix_ver, strict:FALSE) > 0)
  config_check = TRUE;

# Only check configuration if 7.3.0.233 HF263301 or higher is detected
# Look for configurations from KB486276 (https://support.emc.com/kb/486276)
if (config_check)
{
  if (!get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

  # Select transport
  if (islocalhost())
  {
    if (!defined_func("pread"))
      exit(1, "'pread()' is not defined.");
    info_t = INFO_LOCAL;
  }
  else
  {
    sock_g = ssh_open_connection();
    if (!sock_g)
      audit(AUDIT_FN_FAIL, 'ssh_open_connection');
    info_t = INFO_SSH;
  }

  config_check = TRUE;
  path = "/usr/local/avamar/var/mc/server_data/";

  configs = make_array(
    "postgres/data/pg_hba.conf",
      make_list("local all all peer map=mcdb", "hostssl all all samehost cert clientcert=1",
                "host mcdb viewuser 0.0.0.0/0 md5", "host mcdb viewuser ::0/0 md5"),
    "postgres/data/pg_ident.conf",
      make_list("mcdb admin admin", "mcdb admin viewuser", "mcdb root admin", "mcdb root viewuser"),
    "postgres/data/postgresql.conf",
      make_list("ssl = on"),
    "prefs/mcserver.xml",
      make_list('<entry key="database_sslmode" value="true" />')
  );

  foreach subpath (keys(configs))
  {
    content = info_send_cmd(cmd:"cat " + path + subpath);
    foreach config (configs[subpath])
    {
      pattern = str_replace(string:config, find:" ", replace:'\\s+');
      pattern = '^\\s*' + pattern + '\\s*';
      if (!preg(string:content, pattern:pattern, icase:TRUE, multiline:TRUE))
      {
        insecure_file = path + subpath;
        report_fix = "Apply the configurations as documented in KB486276." +
          '\n  Insecure file     : ' + insecure_file ;         
        vuln = TRUE;
        break;
      }
    }
    if (vuln) break;
  } 
}
else
{
  report_fix =
    fix_ver + " HF" + fix_hf + " and apply the configurations as documented in KB486276.";
}

if (!vuln)
  audit(AUDIT_INST_VER_NOT_VULN, app, version_ui);

report =
  '\n  Installed version : ' + version_ui +
  '\n  Fixed version     : ' + report_fix +
  '\n';

security_report_v4(
  extra    : report,
  port     : port,
  severity : SECURITY_HOLE
);
