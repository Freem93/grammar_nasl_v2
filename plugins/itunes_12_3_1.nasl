#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86602);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:42:40 $");

  script_cve_id(
    "CVE-2015-5928",
    "CVE-2015-5929",
    "CVE-2015-5930",
    "CVE-2015-5931",
    "CVE-2015-6975",
    "CVE-2015-6992",
    "CVE-2015-7002",
    "CVE-2015-7011",
    "CVE-2015-7012",
    "CVE-2015-7013",
    "CVE-2015-7014",
    "CVE-2015-7017"
  );
  script_osvdb_id(
    129215,
    129216,
    129217,
    129218,
    129219,
    129220,
    129221,
    129222,
    129223,
    129232,
    129233,
    129234
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-10-21-5");

  script_name(english:"Apple iTunes < 12.3.1 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks the version of iTunes on Windows.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is
prior to 12.3.1. It is, therefore, affected by multiple
vulnerabilities due to memory corruption issues in the WebKit and
CoreText components. An attacker can exploit these to cause a denial
of service or execute arbitrary code.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205372");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("installed_sw/iTunes Version", "SMB/Registry/Enumerated");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

# Ensure this is Windows
get_kb_item_or_exit("SMB/Registry/Enumerated");

app_id = 'iTunes Version';
install = get_single_install(app_name:app_id, exit_if_unknown_ver:TRUE);

version = install["version"];
path = install["path"];

fixed_version = "12.3.1.23";
if (ver_compare(ver:version, fix:fixed_version) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "iTunes", version, path);
