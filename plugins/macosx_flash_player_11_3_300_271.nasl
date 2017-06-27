#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61551);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id("CVE-2012-1535");
  script_bugtraq_id(55009);
  script_osvdb_id(84607);

  script_name(english:"Flash Player for Mac <= 11.3.300.270 Code Execution (APSB12-18)");
  script_summary(english:"Checks version of Flash Player");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host has a browser plugin that is affected by a
remote code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the instance of Flash Player installed on the
remote Mac OS X host is 11.x equal to or earlier than 11.3.300.270.  It
is, therefore, potentially affected by an unspecified remote code
execution vulnerability.

Also note the vendor states 10.x versions are not affected by this
vulnerability and the branch was not updated."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-18.html");
  script_set_attribute(attribute:"see_also", value:"http://forums.adobe.com/thread/1049526");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Flash Player version 11.3.300.271 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player 11.3 Kern Table Parsing Integer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_flash_player_installed.nasl");
  script_require_keys("MacOSX/Flash_Player/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("MacOSX/Flash_Player/Version");

# nb: we're checking for versions less than *or equal to* the cutoff!
elevenx_cutoff_version = "11.3.300.270";
elevenx_fixed_version  = "11.3.300.271";
fixed_version_for_report = NULL;

# 11x
if (
  version =~ "^11\." &&
  ver_compare(ver:version, fix:elevenx_cutoff_version, strict:FALSE) <= 0
) fixed_version_for_report = elevenx_fixed_version;

if (!isnull(fixed_version_for_report))
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : '+fixed_version_for_report+'\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Flash Player for Mac", version);
