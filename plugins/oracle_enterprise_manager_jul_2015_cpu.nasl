#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84879);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/01/27 17:17:23 $");

  script_cve_id(
    "CVE-2015-2646",
    "CVE-2015-2647",
    "CVE-2015-4735"
  );
  script_bugtraq_id(
    75828,
    75834,
    75836
  );
  script_osvdb_id(
    124664,
    124665,
    124666
  );

  script_name(english:"Oracle Enterprise Manager Cloud Control Multiple Vulnerabilities (July 2015 CPU)");
  script_summary(english:"Checks for the patch ID.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an enterprise management application installed
that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Enterprise Manager Cloud Control installed on
the remote host is affected by multiple unspecified flaws in the
'Content Management' and 'RAC Management' subcomponents of the
Enterprise Manager for Oracle Database component. A remote attacker
can exploit these flaws to impact the integrity and confidentiality of
the system.

Note that the product was formerly known as Enterprise Manager Grid
Control.");
  # http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html#AppendixEM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0941d130");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/20");

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

if (version !~ "^11\.1\.0\.1(\.([0-9]|1[01]))?$") audit(AUDIT_HOST_NOT, 'affected');

# Now look for the affected components
patchesinstalled = find_patches_in_ohomes(ohomes:make_list(emchome));
if (isnull(patchesinstalled))
{
  missing = "20436092";
}
else
{
  patched = FALSE;
  foreach patchid (keys(patchesinstalled[emchome]))
  {
    if (patchid == "20436092")
    {
      patched = TRUE;
    }
    else
    {
      foreach bugid (patchesinstalled[emchome][patchid]['bugs'])
      {
        if (bugid == "20436092")
        {
          patched = TRUE;
        }
      }
    }
  }
  if (!patched)
  {
    missing = "20436092";
  }
}

if (empty_or_null(missing)) audit(AUDIT_HOST_NOT, 'affected');

if (report_verbosity > 0)
{
  report +=
    '\n  Product       : ' + product +
    '\n  Version       : ' + version +
    '\n  Missing patch : 20436092' +
    '\n';
  security_warning(port:0, extra:report);
}
else security_warning(0);
