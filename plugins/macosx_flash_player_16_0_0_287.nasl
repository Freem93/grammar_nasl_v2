#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80947);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/17 16:53:09 $");

  script_cve_id("CVE-2015-0310");
  script_bugtraq_id(72261);
  script_osvdb_id(117429);

  script_name(english:"Flash Player For Mac <= 16.0.0.257 Information Disclosure (APSB15-02)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a browser plugin that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Adobe Flash Player
installed on the remote Mac OS X host is equal or prior to 16.0.0.257.
It is, therefore, affected by a memory leak that can allow bypassing
of memory randomization mitigations, aiding in further attacks.");
  script_set_attribute(attribute:"see_also", value:"http://helpx.adobe.com/security/products/flash-player/apsb15-02.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  # http://malware.dontneedcoffee.com/2015/01/unpatched-vulnerability-0day-in-flash.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cdc6d908");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 16.0.0.287 or later.

Alternatively, Adobe has made version 13.0.0.262 available for those
installations that cannot be upgraded to 16.x.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_flash_player_installed.nasl");
  script_require_keys("MacOSX/Flash_Player/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("MacOSX/Flash_Player/Version");
path = get_kb_item_or_exit("MacOSX/Flash_Player/Path");

if (ver_compare(ver:version, fix:"14.0.0.0", strict:FALSE) >= 0)
{
  cutoff_version = "16.0.0.257";
  fix = "16.0.0.287";
}
else
{
  cutoff_version = "13.0.0.260";
  fix = "13.0.0.262";
}

# nb: we're checking for versions less than *or equal to* the cutoff!
if (ver_compare(ver:version, fix:cutoff_version, strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Flash Player for Mac", version, path);
