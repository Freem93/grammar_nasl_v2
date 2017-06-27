#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88043);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/02/09 15:07:54 $");

  script_cve_id(
    "CVE-2015-1793",
    "CVE-2015-4885",
    "CVE-2016-0411",
    "CVE-2016-0415",
    "CVE-2016-0427",
    "CVE-2016-0442",
    "CVE-2016-0443",
    "CVE-2016-0444",
    "CVE-2016-0445",
    "CVE-2016-0446",
    "CVE-2016-0447",
    "CVE-2016-0449",
    "CVE-2016-0455"
  );
  script_bugtraq_id(
    75652,
    81091,
    81111,
    81120,
    81128,
    81131,
    81134,
    81140,
    81144,
    81179,
    81190,
    81194,
    81205
  );
  script_osvdb_id(
    124300,
    133215,
    133216,
    133217,
    133218,
    133219,
    133220,
    133221,
    133222,
    133223,
    133224,
    133225,
    133226
  );
  script_xref(name:"EDB-ID", value:"38640");

  script_name(english:"Oracle Enterprise Manager Cloud Control Multiple Vulnerabilities (January 2016 CPU)");
  script_summary(english:"Checks for the patch ID.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an enterprise management application installed
that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Enterprise Manager Cloud Control installed on
the remote host is affected by multiple unspecified vulnerabilities in
the following subcomponents of the Enterprise Manager Base Platform
component :

  - Agent Next Gen
  - Discovery Framework
  - Loader Service
  - UI Framework

Note that the product was formerly known as Enterprise Manager Grid
Control.");
  # http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html#AppendixEM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e9bccb2");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2016 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/21");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager");
  script_set_attribute(attribute:"plugin_type", value:"local");
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

if (version =~ "^12\.1\.0\.5(\.[0-9])?$")
  patchid = "22115901";
if (version =~ "^12\.1\.0\.4(\.[0-9])?$")
  patchid = "22132672";
if (version =~ "^11\.1\.0\.1(\.[0-9])?$")
  patchid = "22266340";

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

if (report_verbosity > 0)
{
  report +=
    '\n  Product       : ' + product +
    '\n  Version       : ' + version +
    '\n  Missing patch : ' + patchid +
    '\n';
  security_warning(port:0, extra:report);
}
else security_warning(0);
