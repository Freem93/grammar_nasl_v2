#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94250);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/07 21:59:18 $");

  script_cve_id("CVE-2016-5604");
  script_bugtraq_id(93751);
  script_osvdb_id(145876);

  script_name(english:"Oracle Enterprise Manager Cloud Control Security Framework Vulnerability (October 2016 CPU)");
  script_summary(english:"Checks for the patch ID.");

  script_set_attribute(attribute:"synopsis", value:
"An enterprise management application installed on the remote host is
affected by an unspecified vulnerability that impacts confidentiality
and integrity.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Enterprise Manager Cloud Control installed on
the remote host is affected by an unspecified flaw in the Enterprise
Manager Base Platform component, within the Security Framework
subcomponent, that allows a local attacker to impact confidentiality
and integrity. No other details are available.

Note that the product was formerly known as Enterprise Manager Grid
Control.");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html#AppendixEM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4c70039");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2016 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:C/C:L/I:H/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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
patchid = FALSE;

if (version =~ "^12\.1\.0\.5(\.[0-9]+)?$")
  patchid = "24316675";

if (!patchid)
  audit(AUDIT_HOST_NOT, 'affected');

# Now look for the affected components
patchesinstalled = find_patches_in_ohomes(ohomes:make_list(emchome));
if (isnull(patchesinstalled))
{
  missing = patchid;
  patched = FALSE;
}
else
{
  patched = FALSE;
  foreach applied (keys(patchesinstalled[emchome]))
  {
    if (applied == patchid)
    {
      patched = TRUE;
      break;
    }
    else
    {
      foreach bugid (patchesinstalled[emchome][applied]['bugs'])
      {
        if (bugid == patchid)
        {
          patched = TRUE;
          break;
        }
      }
    }
  }
  if (!patched)
  {
    missing = patchid;
  }
}

if (empty_or_null(missing))
  audit(AUDIT_HOST_NOT, 'affected');

order = make_list('Product', 'Version', "Missing patch");
report = make_array(
  order[0], product,
  order[1], version,
  order[2], patchid
);
report = report_items_str(report_items:report, ordered_fields:order);

security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
