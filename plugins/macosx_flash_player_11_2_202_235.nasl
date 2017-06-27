#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58995);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id("CVE-2012-0779");
  script_bugtraq_id(53395);
  script_osvdb_id(81656);

  script_name(english:"Flash Player for Mac <= 10.3.183.18 / 11.2.202.233 Object Confusion Vulnerability (APSB12-09)");
  script_summary(english:"Checks version of Flash Player");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host has a browser plugin that is affected by a
code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the instance of Flash Player installed on
the remote Mac OS X host is 10.x equal to or earlier than 10.3.183.18
or 11.x equal to or earlier than 11.2.202.233.  It is, therefore,
reportedly affected by an object confusion vulnerability that could
allow an attacker to crash the application or potentially take control
of the target system. 

By tricking a victim into visiting a specially crafted page, an
attacker may be able to utilize this vulnerability to execute
arbitrary code subject to the users' privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-09.html");
  #http://blogs.technet.com/b/mmpc/archive/2012/05/24/a-technical-analysis-of-adobe-flash-player-cve-2012-0779-vulnerability.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba4bc112");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Adobe Flash Player version 10.3.183.19 / 11.2.202.235 or
later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player Object Type Confusion');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/04");

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


include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("MacOSX/Flash_Player/Version");

# nb: we're checking for versions less than *or equal to* the cutoff!
tenx_cutoff_version    = "10.3.183.18";
tenx_fixed_version     = "10.3.183.19";
elevenx_cutoff_version = "11.2.202.233";
elevenx_fixed_version  = "11.2.202.235";
fixed_version_for_report = NULL;

# 10x
if (ver_compare(ver:version, fix:tenx_cutoff_version, strict:FALSE) <= 0)
  fixed_version_for_report = tenx_fixed_version;

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
