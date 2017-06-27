#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93654);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_cve_id("CVE-2016-5309", "CVE-2016-5310");
  script_bugtraq_id(92866, 92868);
  script_osvdb_id(144639, 144640);
  script_xref(name:"IAVA", value:"2016-A-0256");

  script_name(english:"Symantec Protection Engine 7.0.x < 7.0.5 HF02 / 7.5.x < 7.5.5 HF01 / 7.8.x < 7.8.0 HF03 Multiple DoS (SYM16-015)");
  script_summary(english:"Checks the version of Symantec Protection Engine.");

  script_set_attribute(attribute:"synopsis", value:
"A security application installed on the remote host is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Protection Engine (SPE) installed on the
remote Windows host is 7.0.x prior to 7.0.5 hotfix 02, 7.5.x prior to
7.5.5 hotifx 01, or 7.8.x prior to 7.8.0 hotifx 03. It is, therefore,
affected by multiple denial of service vulnerabilities :

  - A denial of service vulnerability exists in the
    decomposer engine due to an out-of-bounds read error
    that occurs when decompressing RAR archives. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted RAR file, to crash the application.
    (CVE-2016-5309)

  - A denial of service vulnerability exists in the
    decomposer engine due to memory corruption issue that
    occurs when decompressing RAR archives. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted RAR file, to crash the application.
    (CVE-2016-5310)");
  # https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160919_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4125a0d");
  script_set_attribute(attribute:"see_also", value:"https://support.symantec.com/en_US/article.INFO3791.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Protection Engine (SPE) version 7.0.5 HF02 / 7.5.5
HF01 / 7.8.0 HF03 or later per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:protection_engine");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_scan_engine_installed.nasl");
  script_require_keys("SMB/symantec_scan_engine/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

app = 'Symantec Protection Engine';

function check_hf(path)
{
  local_var loc, locs, content;
  local_var line, matches, vuln;

  vuln = FALSE;

  hotfix_check_fversion_init();

  locs  = make_list(path, path + "Definitions\Decomposer\");

  foreach loc(locs)
  {
    if (hotfix_check_fversion(file:"dec2.dll", version:"5.4.7.5", path:loc))
    {
      vuln = TRUE;
      break;
    }
  }

  hotfix_check_fversion_end();

  return vuln;
}

port = kb_smb_transport();

path = get_kb_item_or_exit("Symantec/Symantec Protection Engine/Path");
version = get_kb_item_or_exit("Symantec/Symantec Protection Engine/Version");

fix = NULL;

if (version =~ "^7\.0\.[0-9.]+$")
{
  if (
    version =~ "^7\.0\.5\." &&
    check_hf(path:path)
  ) fix = "7.0.5.x with HF02 applied";

  if (version =~ "^7\.0\.[0-4]\.")
    fix = "7.0.5.x with HF02 applied";
}
else if (version =~ "^7\.5\.[0-9.]+$")
{
  if (
    version =~ "^7\.5\.5\." &&
    check_hf(path:path)
  ) fix = "7.5.5.x with HF01 applied";

  if (version =~ "^7\.5\.[0-4]\.")
    fix = "7.5.5.x with HF01 applied";
}
else if (version =~ "^7\.8\.[0-9.]+$")
{
  if (
    version =~ "^7\.8\.0\." &&
    check_hf(path:path)
  ) fix = "7.8.0.x with HF03 applied";
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

if (!empty_or_null(fix))
{
  report = report_items_str(
    report_items:make_array(
      "Path", path,
      "Installed version", version,
      "Fixed version", fix
    ),
    ordered_fields:make_list("Path", "Installed version", "Fixed version")
  );

  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
