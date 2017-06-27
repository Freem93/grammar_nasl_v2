#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82855);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/01/27 17:17:23 $");

  script_cve_id("CVE-2015-0473");
  script_bugtraq_id(74077);
  script_osvdb_id(120679);

  script_name(english:"Oracle Enterprise Manager Cloud Control Unspecified Vulnerability (April 2015 CPU)");
  script_summary(english:"Checks for the patch ID.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an enterprise management application installed
that is affected by an unspecified vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Enterprise Manager Cloud Control installed on
the remote host is affected by an unspecified flaw in the My Oracle
Support Plugin subcomponent of the Enterprise Manager Base Platform
component. A remote attacker can exploit this to impact the integrity
of the system.

Note that the product was formerly known as the Enterprise Manager
Grid Control.");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html#AppendixEM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6453ec36");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/17");

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

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("oracle_rdbms_cpu_func.inc");
include("install_func.inc");

product = "Oracle Enterprise Manager Cloud Control";
install = get_single_install(app_name:product, exit_if_unknown_ver:TRUE);
version = install['version'];
emchome = install['path'];

patches = make_array();
if (version !~ "^12\.1\.0\.(3(\.[0-2])?$|4(\.[0-2])?$)") audit(AUDIT_HOST_NOT, 'affected');
if (emchome =~ '^[A-Za-z]:.*')
{
  wls_home = ereg_replace(string:emchome, pattern:'^([A-Za-z]:.*\\\\)oms(\\\\)?$', replace:"\1");
  separator = "\";
}
else
{
  wls_home = ereg_replace(string:emchome, pattern:'^(/.*/)oms(/)?$', replace:"\1");
  separator = "/";
}

if (version =~ "^12\.1\.0\.3(\.[0-2])?$")
{
  patches["oracle.sysman.mos.plugin.oms"]["patchid"] = "20391018";
  patches["oracle.sysman.mos.plugin.oms"]["path"] = wls_home + "plugins" + separator + "oracle.sysman.mos.oms.plugin_12.1.0.5.0";
}
else if (version =~ "^12\.1\.0\.4(\.[0-2])?$")
{
  patches["oracle.sysman.mos.plugin.oms"]["patchid"] = "20613886";
  patches["oracle.sysman.mos.plugin.oms"]["path"] = wls_home + "plugins" + separator + "oracle.sysman.mos.oms.plugin_12.1.0.6.0";
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
