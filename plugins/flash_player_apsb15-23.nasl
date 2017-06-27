#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86060);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/18 04:40:37 $");

  script_cve_id(
    "CVE-2015-5567",
    "CVE-2015-5568",
    "CVE-2015-5570",
    "CVE-2015-5571",
    "CVE-2015-5572",
    "CVE-2015-5573",
    "CVE-2015-5574",
    "CVE-2015-5575",
    "CVE-2015-5576",
    "CVE-2015-5577",
    "CVE-2015-5578",
    "CVE-2015-5579",
    "CVE-2015-5580",
    "CVE-2015-5581",
    "CVE-2015-5582",
    "CVE-2015-5584",
    "CVE-2015-5587",
    "CVE-2015-5588",
    "CVE-2015-6676",
    "CVE-2015-6677",
    "CVE-2015-6678",
    "CVE-2015-6679",
    "CVE-2015-6682"
  );
  script_osvdb_id(
    127803,
    127804,
    127805,
    127806,
    127807,
    127808,
    127809,
    127810,
    127811,
    127812,
    127813,
    127814,
    127815,
    127816,
    127817,
    127818,
    127819,
    127820,
    127821,
    127822,
    127823,
    127824,
    127825
  );

  script_name(english:"Adobe Flash Player <= 18.0.0.232 Multiple Vulnerabilities (APSB15-23)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Windows host
is equal or prior to version 18.0.0.232. It is, therefore, affected by
multiple vulnerabilities :

  - An unspecified stack corruption issue exists that
    allows a remote attacker to execute arbitrary code.
    (CVE-2015-5567, CVE-2015-5579)

  - A vector length corruption issue exists that allows a
    remote attacker to have an unspecified impact.
    (CVE-2015-5568)

  - A use-after-free error exists in an unspecified
    component due to improperly sanitized user-supplied
    input. A remote attacker can exploit this, via a
    specially crafted file, to deference already freed
    memory and execute arbitrary code. (CVE-2015-5570,
    CVE-2015-5574, CVE-2015-5581, CVE-2015-5584,
    CVE-2015-6682)

  - An unspecified flaw exists due to a failure to reject
    content from vulnerable JSONP callback APIs. A remote
    attacker can exploit this to have an unspecified impact.
    (CVE-2015-5571)

  - An unspecified flaw exists that allows a remote attacker
    to bypass security restrictions and gain access to
    sensitive information. (CVE-2015-5572)

  - An unspecified type confusion flaw exists that allows a
    remote attacker to execute arbitrary code.
    (CVE-2015-5573)

  - A flaw exists in an unspecified component due to
    improper validation of user-supplied input when handling
    a specially crafted file. A remote attacker can exploit
    this to corrupt memory, resulting in a denial of service
    or the execution of arbitrary code. (CVE-2015-5575,
    CVE-2015-5577, CVE-2015-5578, CVE-2015-5580,
    CVE-2015-5582, CVE-2015-5588, CVE-2015-6677)

  - A memory leak issue exists that allows a remote
    attacker to have an unspecified impact. (CVE-2015-5576)

  - A stack buffer overflow condition exists due to improper
    validation of user-supplied input. A remote attacker can
    exploit this to execute arbitrary code. (CVE-2015-5587)

  - An unspecified overflow condition exists due to improper
    validation of user-supplied input. A remote attacker can
    exploit this to execute arbitrary code. (CVE-2015-6676,
    CVE-2015-6678)

  - An unspecified flaw exists that allows a remote attacker
    to bypass same-origin policy restrictions and gain
    access to sensitive information. (CVE-2015-6679)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-23.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 19.0.0.185 or later.

Alternatively, Adobe has made version 18.0.0.241 available for those
installations that cannot be upgraded to the latest version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("flash_player_installed.nasl");
  script_require_keys("SMB/Flash_Player/installed");

  exit(0);
}

include("audit.inc");
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

    # Chrome Flash <= 18.0.0.233
    if(variant == "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"18.0.0.233",strict:FALSE) <= 0
    ) vuln = TRUE;

    # <= 18.0.0.232
    if(variant != "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"18.0.0.232",strict:FALSE) <= 0
    ) vuln = TRUE;

    # 14-17 <= 18.0.0.232
    if(variant != "Chrome_Pepper" &&
       ver =~ "^1[45678]\." &&
       ver_compare(ver:ver,fix:"18.0.0.232",strict:FALSE) <= 0
    ) vuln = TRUE;

    if(vuln)
    {
      num = key - ("SMB/Flash_Player/"+variant+"/Version/");
      file = files["SMB/Flash_Player/"+variant+"/File/"+num];
      if (variant == "Plugin")
      {
        info += '\n Product : Browser Plugin (for Firefox / Netscape / Opera)';
        fix = "19.0.0.185 / 18.0.0.241";
      }
      else if (variant == "ActiveX")
      {
        info += '\n Product : ActiveX control (for Internet Explorer)';
        fix = "19.0.0.185 / 18.0.0.241";
      }
      else if ("Chrome" >< variant)
      {
        info += '\n Product : Browser Plugin (for Google Chrome)';
        if(variant == "Chrome")
          fix = "Upgrade to a version of Google Chrome running Flash Player 19.0.0.185";
      }
      info += '\n  Path              : ' + file +
              '\n  Installed version : ' + ver;
      if (variant == "Chrome_Pepper")
        info += '\n  Fixed version     : 19.0.0.185 (Chrome PepperFlash)';
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
    audit(AUDIT_INST_VER_NOT_VULN, "Adobe Flash Player");
  else
    exit(1, 'Google Chrome\'s built-in Flash Player may not have been detected because the \'Perform thorough tests\' setting was not enabled.');
}
