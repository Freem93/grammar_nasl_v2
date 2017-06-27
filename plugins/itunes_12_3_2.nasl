#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87371);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:42:40 $");

  script_cve_id(
    "CVE-2015-7048",
    "CVE-2015-7050",
    "CVE-2015-7095",
    "CVE-2015-7096",
    "CVE-2015-7097",
    "CVE-2015-7098",
    "CVE-2015-7099",
    "CVE-2015-7100",
    "CVE-2015-7101",
    "CVE-2015-7102",
    "CVE-2015-7103",
    "CVE-2015-7104"
  );
  script_bugtraq_id(
    78720,
    78722,
    78726
  );
  script_osvdb_id(
    131370,
    131371,
    131372,
    131373,
    131374,
    131375,
    131376,
    131377,
    131378,
    131379,
    131380,
    131440
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-12-11-1");

  script_name(english:"Apple iTunes < 12.3.2 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks the version of iTunes on Windows.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is
prior to 12.3.2. It is, therefore, affected by multiple
vulnerabilities in the WebKit component :

  - Multiple memory corruption issues exists that an
    attacker can exploit to cause a denial of service or
    execute arbitrary code. (CVE-2015-7048, CVE-2015-7095,
    CVE-2015-7096, CVE-2015-7097, CVE-2015-7098,
    CVE-2015-7099, CVE-2015-7100, CVE-2015-7101,
    CVE-2015-7102, CVE-2015-7103, CVE-2015-7104)

  - A flaw exists in content blocking due to improper
    validation of input. A remote attacker can exploit this,
    via a malicious website, to reveal the user's browsing
    history. (CVE-2015-7050)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205636");
  # https://lists.apple.com/archives/security-announce/2015/Dec/msg00006.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3562e993");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/15");

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

fixed_version = "12.3.2.35";
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
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "iTunes", version, path);
