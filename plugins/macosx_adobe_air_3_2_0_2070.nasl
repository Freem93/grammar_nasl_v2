#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58539);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/07/28 20:23:55 $");

  script_cve_id("CVE-2012-0772", "CVE-2012-0773");
  script_bugtraq_id(52748);
  script_osvdb_id(80706, 80707);

  script_name(english:"Adobe AIR for Mac 3.x <= 3.1.0.4880 Multiple Memory Corruption Vulnerabilities (APSB12-07)");
  script_summary(english:"Checks version gathered by local check");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host contains a version of Adobe AIR that is
affected by multiple memory corruption vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the instance of Adobe AIR 3.x on the remote
Mac OS X host is 3.1.0.4880 or earlier and is reportedly affected by
several critical memory corruption vulnerabilities :

  - Memory corruption vulnerabilities related to URL 
    security domain checking. (CVE-2012-0772)

  - A flaw in the NetStream Class that could lead to remote
    code execution. (CVE-2012-0773)

By tricking a victim into visiting a specially crafted page, an
attacker may be able to utilize these vulnerabilities to execute
arbitrary code subject to the users' privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-07.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe AIR 3.2.0.2070 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_adobe_air_installed.nasl");
  script_require_keys("MacOSX/Adobe_AIR/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


kb_base = "MacOSX/Adobe_AIR";
version = get_kb_item_or_exit(kb_base+"/Version");


# nb: we're checking for versions less than *or equal to* the cutoff!
cutoff_version = '3.1.0.4880';
fixed_version_for_report = '3.2.0.2070';

if (
  version =~ "^3\." && 
  ver_compare(ver:version, fix:cutoff_version, strict:FALSE) <= 0
)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item_or_exit(kb_base+"/Path");
    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : '+fixed_version_for_report+'\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else exit(0, "The Adobe AIR for Mac "+version+" install is not affected.");
