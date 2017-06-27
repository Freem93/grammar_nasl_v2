#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72938);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/20 14:12:04 $");

  script_cve_id("CVE-2014-0503", "CVE-2014-0504");
  script_bugtraq_id(66122, 66127);
  script_osvdb_id(104318, 104319);

  script_name(english:"Flash Player for Mac <= 11.7.700.269 / 12.0.0.70 Multiple Vulnerabilities (APSB14-08) (Mac OS X)");
  script_summary(english:"Checks version of Flash Player");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host has a browser plugin that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the instance of Flash Player installed on
the remote Mac OS X host is equal or prior to 11.7.700.269 / 11.8.x /
11.9.x / 12.0.0.70.  It is, therefore, potentially affected by
multiple vulnerabilities :

  - A vulnerability exists that could be used to bypass the
    same origin policy. (CVE-2014-0503)

  - A vulnerability exists that could be used to read the
    contents of the clipboard. (CVE-2014-0504)"
  );
  script_set_attribute(attribute:"see_also", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-08.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 11.7.700.272 / 12.0.0.77 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_flash_player_installed.nasl");
  script_require_keys("MacOSX/Flash_Player/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("MacOSX/Flash_Player/Version");
path = get_kb_item_or_exit("MacOSX/Flash_Player/Path");

# nb: we're checking for versions less than *or equal to* the cutoff!
extended_cutoff_version = "11.7.700.269";
extended_fixed_version = "11.7.700.272";

standard_cutoff_version = "12.0.0.70";
standard_fixed_version  = "12.0.0.77";

fixed_version_for_report = NULL;

if (version =~ "^([0-9]|10)\.|^11\.[0-6]")
  fixed_version_for_report = extended_fixed_version;

else if (
  version =~ "^11\.7\." &&
  ver_compare(ver:version, fix:extended_cutoff_version, strict:FALSE) <= 0
) fixed_version_for_report = extended_fixed_version;

else if (version =~ "^11\.[89]\.") fixed_version_for_report = standard_fixed_version;
else if (
  version =~ "^12\.0\.0\." &&
  ver_compare(ver:version, fix:standard_cutoff_version, strict:FALSE) <= 0
) fixed_version_for_report = standard_fixed_version;

if (!isnull(fixed_version_for_report))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version_for_report +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Flash Player for Mac", version, path);
