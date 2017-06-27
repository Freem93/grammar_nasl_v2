#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80966);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/01/27 17:17:23 $");

  script_cve_id("CVE-2011-4461", "CVE-2014-4212", "CVE-2015-0426");
  script_bugtraq_id(51199, 68638, 72235);
  script_osvdb_id(78117, 109092, 117245);

  script_name(english:"Oracle Enterprise Manager Cloud Control Multiple Vulnerabilities (January 2015 CPU)");
  script_summary(english:"Checks for the patch ID.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an enterprise management application installed
that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Enterprise Manager Cloud Control installed on
the remote host is affected by vulnerabilities in the following
subcomponents of the Enterprise Manager Base Platform component :

  - Agent
  - UI Framework
  - Process Management & Notification

Note that the product was formerly known as the Enterprise Manager
Grid Control.");
  # http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html#AppendixEM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7996082");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/26");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_enterprise_manager_installed.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Manager Cloud Control");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("oracle_rdbms_cpu_func.inc");
include("install_func.inc");

product = "Oracle Enterprise Manager Cloud Control";
install = get_single_install(app_name:product, exit_if_unknown_ver:TRUE);
version = install['version'];
emchome = install['path'];

patches = make_array();
if (version !~ "^12\.1\.0\.(3(\.[0-2])?$|4(\.[01])?$)") audit(AUDIT_HOST_NOT, 'affected');
wls_home = str_replace(find:'oms', replace:'', string:emchome);
if (emchome =~ '^[A-Za-z]:.*')
{
  wls_home = ereg_replace(string:emchome, pattern:'^([A-Za-z]:.*\\\\)oms(\\\\)?$', replace:"\1");
  separator = '\\';
}
else
{
  wls_home = ereg_replace(string:emchome, pattern:'^(/.*/)oms(/)?$', replace:"\1");
  separator = "/";
}

if (version =~ "^12\.1\.0\.3(\.[0-2])?$")
{
  patches["oracle.as.webtiercd.top"]["patchid"] = "17988318";
  patches["oracle.as.webtiercd.top"]["path"] = wls_home + "Oracle_WT" + separator;
  patches["oracle.sysman.common.core"]["patchid"] = "17617669";
  patches["oracle.sysman.common.core"]["path"] = wls_home + "oracle_common" + separator;
  patches["oracle.sysman.top.agent"]["patchid"] = "19930706";

  ohomes = make_list();
  res = query_scratchpad("SELECT path FROM oracle_homes");
  if (empty_or_null(res)) exit(1, 'Unable to obtain Oracle Homes');
  foreach ohome (res)
    ohomes = make_list(ohomes, ohome['path']);
  foreach ohome (ohomes)
  {
    res = find_oracle_component_in_ohome(ohome:ohome, compid:'oracle.sysman.top.agent');
    if (!empty_or_null(res))
    {
      patches["oracle.sysman.top.agent"]["path"] = ohome;
      break;
    }
  }
}
else if (version =~ "^12\.1\.0\.4(\.[01])?$")
{
  patches["oracle.as.webtiercd.top"]["patchid"] = "19345576";
  patches["oracle.as.webtiercd.top"]["path"] = wls_home + "Oracle_WT" ;
  patches["oracle.sysman.common.core"]["patchid"] = "17617649";
  patches["oracle.sysman.common.core"]["path"] = wls_home + "oracle_common";
}

# Now look for the affected components
missing = make_list();
foreach comp (keys(patches))
{
  ohome = patches[comp]["path"];
  patchesinstalled = find_patches_in_ohomes(ohomes:make_list(ohome));
  if (isnull(patchesinstalled))
  {
    missing = make_list(missing, patches[comp]["patchid"]);
  }
  else
  {
    patched = FALSE;
    foreach patchid (keys(patchesinstalled[ohome]))
    {
      if (patchid == patches[comp]["patchid"])
      {
        patched = TRUE;
      }
      else
      {
        foreach bugid (patchesinstalled[ohome][patchid]['bugs'])
        {
          if (bugid == patches[comp]["patchid"])
          {
            patched = TRUE;
          }
        }
      }
    }
    if (!patched)
    {
      missing = make_list(missing, patches[comp]["patchid"]);
    }
  }
}

if (max_index(keys(missing)) == 0) audit(AUDIT_HOST_NOT, 'affected');

if (report_verbosity > 0)
{
  report +=
    '\n  Product       : ' + product +
    '\n  Version       : ' + version +
    '\n  Missing patch : ' + join(missing, sep:',') +
    '\n';
  security_warning(port:0, extra:report);
}
else security_warning(0);
