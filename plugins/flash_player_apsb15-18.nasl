#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84730);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/13 15:19:32 $");

  script_cve_id("CVE-2015-5122", "CVE-2015-5123");
  script_bugtraq_id(75710, 75712);
  script_osvdb_id(124416, 124424);
  script_xref(name:"CERT", value:"338736");
  script_xref(name:"CERT", value:"918568");

  script_name(english:"Adobe Flash Player <= 18.0.0.203 Multiple RCE Vulnerabilities (APSB15-18)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Windows host
is equal or prior to version 18.0.0.203. It is, therefore, affected by
multiple remote code execution vulnerabilities :

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
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("flash_player_installed.nasl");
  script_require_keys("SMB/Flash_Player/installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Flash_Player/installed");

# Identify vulnerable versions.
info = "";
variants = make_list(
  "Plugin",
  "ActiveX",
  "Chrome",
  "Chrome_Pepper"
);

# we're checking for versions less than *or equal to* the cutoff!
foreach variant (variants)
{
  vers = get_kb_list("SMB/Flash_Player/"+variant+"/Version/*");
  files = get_kb_list("SMB/Flash_Player/"+variant+"/File/*");

  if(isnull(vers) || isnull(files))
    continue;

  foreach key (keys(vers))
  {
    ver = vers[key];
    if(isnull(ver))
      continue;

    vuln = FALSE;

    # Chrome Flash <= 18.0.0.203
    if(variant == "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"18.0.0.203",strict:FALSE) <= 0
    ) vuln = TRUE;

    # <= 13.0.0.302.
    if(variant != "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"13.0.0.302",strict:FALSE) <= 0
    ) vuln = TRUE;

    # 14-18 <= 18.0.0.203
    if(variant != "Chrome_Pepper" &&
       ver =~ "^1[4-8]\." &&
       ver_compare(ver:ver,fix:"18.0.0.203",strict:FALSE) <= 0
    ) vuln = TRUE;

    if(vuln)
    {
      num = key - ("SMB/Flash_Player/"+variant+"/Version/");
      file = files["SMB/Flash_Player/"+variant+"/File/"+num];
      if (variant == "Plugin")
      {
        info += '\n Product : NPAPI Browser plugin (for Firefox / Netscape / Opera)';
        fix = "18.0.0.209 / 13.0.0.309";
      }
      else if (variant == "ActiveX")
      {
        info += '\n Product : ActiveX control (for Internet Explorer)';
        fix = "18.0.0.209 / 13.0.0.309";
      }
      else if (variant == "Chrome")
      {
        info += '\n Product : Browser plugin (for Google Chrome)';
        fix = "Upgrade to the latest version of Google Chrome.";
      }
      else if (variant == "Chrome_Pepper")
      {
        info += '\n Product : PPAPI Browser plugin (for Opera and Chromium)';
      }
      info += '\n  Path              : ' + file +
              '\n  Installed version : ' + ver;
      if (variant == "Chrome_Pepper")
        info += '\n  Fixed version     : 18.0.0.209 (Chrome PepperFlash)';
      else if(!isnull(fix))
        info += '\n  Fixed version     : '+fix;
      info += '\n';
    }
  }
}

if (info)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0) security_hole(port:port, extra:info);
  else security_hole(port);
}
else
{
  if (thorough_tests)
    exit(0, 'No vulnerable versions of Adobe Flash Player were found.');
  else
    exit(1, 'Google Chrome\'s built-in Flash Player may not have been detected because the \'Perform thorough tests\' setting was not enabled.');
}
