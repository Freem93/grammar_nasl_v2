#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59069);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/13 15:33:29 $");

  script_cve_id(
    "CVE-2011-3046",
    "CVE-2011-3056",
    "CVE-2012-0672",
    "CVE-2012-0676"
  );
  script_bugtraq_id(52369, 53404, 53407, 53446);
  script_osvdb_id(79893, 80294, 81787, 81792);

  script_name(english:"Safari < 5.1.7 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Safari");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a web browser that is affected by several
issues."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Safari installed on the remote host reportedly is
affected by several issues :

  - Two unspecified errors exist that can allow malicious
    sites to perform cross-site scripting attacks.
    (CVE-2011-3046, CVE-2011-3056)

  - An unspecified memory corruption error exists that can
    allow malicious sites to crash the application or
    potentially execute arbitrary code. (CVE-2012-0672)

  - A state-tracking issue exists that can allow malicious
    sites to populate HTML form values of other sites with
    arbitrary data. (CVE-2012-0676)"
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5282");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/May/msg00002.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Safari 5.1.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("safari_installed.nasl");
  script_require_keys("SMB/Safari/FileVersion");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Safari/FileVersion");

version_ui = get_kb_item("SMB/Safari/ProductVersion");
if (isnull(version_ui)) version_ui = version;

fixed_version = '5.34.57.2';
fixed_version_ui = '5.1.7 (7534.57.2)';

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  port = get_kb_item("SMB/transport");
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    path = get_kb_item("SMB/Safari/Path");
    if (isnull(path)) path = "n/a";

    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_ui +
      '\n  Fixed version     : ' + fixed_version_ui + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Safari", version_ui);
