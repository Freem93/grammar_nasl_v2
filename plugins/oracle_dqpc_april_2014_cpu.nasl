#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73826);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/08 22:17:48 $");

  script_cve_id(
    "CVE-2014-2407",
    "CVE-2014-2415",
    "CVE-2014-2416",
    "CVE-2014-2417",
    "CVE-2014-2418"
  );
  script_bugtraq_id(66836, 66841, 66842, 66844, 66845);
  script_osvdb_id(105819, 105820, 105821, 105822, 105823);

  script_name(english:"Oracle Data Quality and Profiling Client Multiple Vulnerabilities (April 2014 CPU)");
  script_summary(english:"Checks versions");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has software installed that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to the version of the Oracle Data Quality and Profiling
client installed on the remote host, it is affected by multiple
unspecified ActiveX control vulnerabilities. By tricking a user into
opening a specially crafted document, an attacker may be able to
execute arbitrary code.");
  script_set_attribute(attribute:"see_also",value:"http://www.zerodayinitiative.com/advisories/ZDI-14-107/");
  script_set_attribute(attribute:"see_also",value:"http://www.zerodayinitiative.com/advisories/ZDI-14-108/");
  script_set_attribute(attribute:"see_also",value:"http://www.zerodayinitiative.com/advisories/ZDI-14-109/");
  script_set_attribute(attribute:"see_also",value:"http://www.zerodayinitiative.com/advisories/ZDI-14-110/");
  script_set_attribute(attribute:"see_also",value:"http://www.zerodayinitiative.com/advisories/ZDI-14-111/");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef1fc2a6");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2014 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("oracle_data_quality_and_profiling_client_installed.nbin");
  script_require_keys("Oracle/ODQPC/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "Oracle Data Quality and Profiling Client";

get_kb_item_or_exit("Oracle/ODQPC/Installed");
installs = get_kb_list_or_exit("Oracle/ODQPC/*/Version");

report = '';

versions = make_list();

fix = "12.0.1.14034";
patch_num = "18177015";

file_ver_fail = FALSE;

# only 11.1.1.3 affected
foreach key (keys(installs))
{
  version = installs[key];
  if (version !~ "^11\.1\.1\.3($|\.)") continue;

  key -= '/Version';

  path = key - 'Oracle/ODQPC/';

  file_ver = get_kb_item(key + "/File_Version");
  if (isnull(file_ver))
  {
   file_ver_fail = TRUE;
   continue;
  }

  versions = make_list(versions, version + ' (' + file_ver + ')');

  if (ver_compare(fix:fix, ver:file_ver, strict:FALSE) == -1)
  {
    report += '\n  Version            : ' + version +
              '\n  Path               : ' + path +
              '\n  File version       : ' + file_ver +
              '\n  Fixed file version : ' + fix +
              '\n  Required patch     : ' + patch_num + '\n';
  }
}

versions = list_uniq(versions);

if (report != '')
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  if (report_verbosity > 0) security_hole(port:port, extra:report);
  else security_hole(port);
}
else
{
  if (!file_ver_fail) audit(AUDIT_INST_VER_NOT_VULN, appname, versions);
  else exit(0, "No vulnerable " + appname + " version found. Note that results may be incomplete due to missing file version information for one or more installs.");
}
