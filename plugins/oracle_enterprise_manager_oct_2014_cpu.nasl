#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78548);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/01/27 17:17:23 $");

  script_cve_id("CVE-2014-6488");
  script_bugtraq_id(70506);
  script_osvdb_id(113301);

  script_name(english:"Oracle Enterprise Manager Content Management Sub-Component Unspecified Vulnerability (October 2014 CPU)");
  script_summary(english:"Checks for patch ID.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an enterprise management application that is
affected by an unspecified vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Enterprise Manager for Oracle Database installed
on the remote host is affected by an unspecified vulnerability in the
Content Management sub-component.");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6dcc7b47");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2014 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/17");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_enum_products_nix.nbin", "oracle_enum_products_win.nbin");
  script_require_keys("Oracle/Products/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("oracle_rdbms_cpu_func.inc");

get_kb_item_or_exit("Oracle/Products/Installed");
affected_found = FALSE;

comps = make_array();
comps['oracle.sysman.db.plugin.oms']['12.1.0.4'] = make_array('patch', '19281602', 'ohomes', make_list());
comps['oracle.sysman.db.plugin.oms']['12.1.0.5'] = make_array('patch', '19281634', 'ohomes', make_list());
comps['oracle.sysman.oms.core']['12.1.0.3'] = make_array('patch', '18604893', 'ohomes', make_list());
comps['oracle.if.adfrt']['11.1.1.7'] = make_array('patch', '19591065', 'ohomes', make_list());
comps['oracle.sysman.top.oms']['10.2.0.5'] = make_array('patch', '19281059', 'ohomes', make_list());

ohomes = make_list();
res = query_scratchpad("SELECT path FROM oracle_homes");
if (empty_or_null(res)) exit(1, 'Unable to obtain Oracle Homes');
foreach ohome (res)
  ohomes = make_list(ohomes, ohome['path']);

# Now look for the affected components
foreach comp (keys(comps))
{
  foreach ohome (ohomes)
  {
    compversions = keys(comps[comp]);
    # Look for the component in the Oracle home
    res = find_oracle_component_in_ohome(ohome:ohome, compid:comp);
    if (!empty_or_null(res))
    {
      # If a version was found, make sure it is one of the ones we are looking for
      foreach version (compversions)
      {
        if (ereg(pattern:'^' + version + '([^0-9]|$)', string:res))
        {
          affectedfound = TRUE;
          comps[comp][version]['ohomes'] = make_list(comps[comp][version]['ohomes'], ohome);
        }
      }
    }
  }
}

if (!affectedfound)
  exit(0, "None of the affected components were found on the remote host.");

missing = make_array();

# Loop over the components again
foreach comp (keys(comps))
{
  foreach ver (keys(comps[comp]))
  {
    # If the ohomes list is empty, skip
    if (max_index(comps[comp][ver]['ohomes']) == 0) continue;
    patchesinstalled = find_patches_in_ohomes(ohomes:comps[comp][ver]['ohomes']);
    if (isnull(patchesinstalled))
    {
      # No patches have been installed in any of the found oracle homes
      foreach ohome (comps[comp][ver]['ohomes'])
        missing[ohome][comp] = ver;
    }
    else
    {
      # Patches have been installed in at least one Oracle home.
      foreach ohome (keys(patchesinstalled))
      {
        patched = FALSE;
        if (empty_or_null(patchesinstalled[ohome]))
          missing[ohome][comp] = ver;
        else
        {
          foreach patchid (keys(patchesinstalled[ohome]))
          {
            if (patchid == comps[comp][ver]['patch'])
            {
              patched = TRUE;
              break;
            }
            else
            {
              # If the top level patch ID didn't match, check the bugs fixed bug IDs
              foreach bugid (patchesinstalled[ohome][patchid]['bugs'])
              {
                if (bugid = comps[comp][ver]['patch'])
                {
                  patched = TRUE;
                  break;
                }
              }
            }
          }
          if (!patched)
            missing[ohome][comp] = ver;
        }
      }
    }
  }
}

if (max_index(keys(missing)) == 0) audit(AUDIT_HOST_NOT, 'affected');
if (report_verbosity > 0)
{
  if (max_index(keys(missing)) > 1)
    report = 'Nessus found the following vulnerable Oracle homes :\n';
  else
    report = 'Nessus found the following vulnerable Oracle home :\n';

  foreach ohome (keys(missing))
  {
    report += '\n  - ' + ohome;
    foreach component (keys(missing[ohome]))
    {
      report +=
        '\n    Component     : ' + component +
        '\n    Version       : ' + missing[ohome][component] +
        '\n    Missing patch : ' + comps[component][ver]['patch'] +
        '\n\n';
    }
  }
  security_note(port:0, extra:report);
}
else security_note(0);
