#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84732);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/08/18 21:17:56 $");

  script_cve_id("CVE-2015-5122", "CVE-2015-5123");
  script_bugtraq_id(75710, 75712);
  script_osvdb_id(124416, 124424);
  script_xref(name:"CERT", value:"338736");
  script_xref(name:"CERT", value:"918568");

  script_name(english:"Adobe Flash Player <= 18.0.0.203 Multiple RCE Vulnerabilities (APSB15-18) (Mac OS X)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a browser plugin installed that is
affected by multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Mac OS X
host is equal or prior to version 18.0.0.203. It is, therefore,
affected by multiple remote code execution vulnerabilities :

  - A use-after-free error exists in the opaqueBackground
    class in the ActionScript 3 (AS3) implementation. A
    remote attacker, via specially crafted Flash content,
    can dereference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2015-5122)

  - A use-after-free error exists in the BitmapData class in
    the ActionScript 3 (AS3) implementation. A remote
    attacker, via specially crafted Flash content, can
    dereference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2015-5123)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-18.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 18.0.0.209 or later.

Alternatively, Adobe has made version 13.0.0.309 available for those
installations that cannot be upgraded to 18.x.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash opaqueBackground Use After Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/07/10");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/14");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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
  cutoff_version = "18.0.0.203";
  fix = "18.0.0.209";
}
else
{
  cutoff_version = "13.0.0.302";
  fix = "13.0.0.309";
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
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Flash Player for Mac", version, path);
