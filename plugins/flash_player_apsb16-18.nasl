#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91670);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/08/16 13:21:45 $");

  script_cve_id(
    "CVE-2016-4122",
    "CVE-2016-4123",
    "CVE-2016-4124",
    "CVE-2016-4125",
    "CVE-2016-4127",
    "CVE-2016-4128",
    "CVE-2016-4129",
    "CVE-2016-4130",
    "CVE-2016-4131",
    "CVE-2016-4132",
    "CVE-2016-4133",
    "CVE-2016-4134",
    "CVE-2016-4135",
    "CVE-2016-4136",
    "CVE-2016-4137",
    "CVE-2016-4138",
    "CVE-2016-4139",
    "CVE-2016-4140",
    "CVE-2016-4141",
    "CVE-2016-4142",
    "CVE-2016-4143",
    "CVE-2016-4144",
    "CVE-2016-4145",
    "CVE-2016-4146",
    "CVE-2016-4147",
    "CVE-2016-4148",
    "CVE-2016-4149",
    "CVE-2016-4150",
    "CVE-2016-4151",
    "CVE-2016-4152",
    "CVE-2016-4153",
    "CVE-2016-4154",
    "CVE-2016-4155",
    "CVE-2016-4156",
    "CVE-2016-4166",
    "CVE-2016-4171"
  );
  script_osvdb_id(
    139936,
    140015,
    140077,
    140078,
    140079,
    140080,
    140081,
    140082,
    140083,
    140084,
    140085,
    140086,
    140087,
    140088,
    140089,
    140090,
    140091,
    140092,
    140093,
    140094,
    140095,
    140096,
    140097,
    140098,
    140099,
    140100,
    140101,
    140102,
    140103,
    140104,
    140105,
    140106,
    140107,
    140108,
    140109,
    140110
  );
  script_xref(name:"CERT", value:"748992");

  script_name(english:"Adobe Flash Player <= 21.0.0.242 Multiple Vulnerabilities (APSB16-18)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Windows
host is equal or prior to version 21.0.0.242. It is, therefore,
affected by multiple vulnerabilities :

  - Multiple memory corruption issues exist that allow an
    unauthenticated, remote attacker to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2016-4122, CVE-2016-4123, CVE-2016-4124,
    CVE-2016-4125, CVE-2016-4127, CVE-2016-4128,
    CVE-2016-4129, CVE-2016-4130, CVE-2016-4131,
    CVE-2016-4132, CVE-2016-4133, CVE-2016-4134,
    CVE-2016-4137, CVE-2016-4141, CVE-2016-4150,
    CVE-2016-4151, CVE-2016-4152, CVE-2016-4153,
    CVE-2016-4154, CVE-2016-4155, CVE-2016-4156,
    CVE-2016-4166, CVE-2016-4171)

  - Multiple heap buffer overflow conditions exist due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit these to
    execute arbitrary code. (CVE-2016-4135, CVE-2016-4136,
    CVE-2016-4138).

  - An unspecified vulnerability exists that allows an
    unauthenticated, remote attacker to bypass the
    same-origin policy, resulting in the disclosure of
    potentially sensitive information. (CVE-2016-4139)

  - An unspecified flaw exists when loading certain dynamic
    link libraries due to using a search path that includes
    directories which may not be trusted or under the user's
    control. An unauthenticated, remote attacker can exploit
    this, by inserting a specially crafted library in the
    path, to execute arbitrary code in the context of the
    user. (CVE-2016-4140)

  - Multiple use-after-free errors exist that allow an
    unauthenticated, remote attacker to deference already
    freed memory, resulting in the execution of arbitrary
    code. (CVE-2016-4142, CVE-2016-4143, CVE-2016-4145,
    CVE-2016-4146, CVE-2016-4147, CVE-2016-4148)

  - Multiple type confusion errors exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-4144, CVE-2016-4149)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-18.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 22.0.0.192 or later.

Alternatively, Adobe has made version 18.0.0.360 available for those
installations that cannot be upgraded to the latest version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

    # Chrome Flash <= 21.0.0.242
    if(variant == "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"21.0.0.242",strict:FALSE) <= 0
    ) vuln = TRUE;

    # <= 18.0.0.352
    if(variant != "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"18.0.0.352",strict:FALSE) <= 0
    ) vuln = TRUE;

    # 19 <= 21.0.0.242
    else if(variant != "Chrome_Pepper" &&
      ver =~ "^(?:19|[2-9]\d)\." &&
      ver_compare(ver:ver,fix:"21.0.0.242",strict:FALSE) <= 0
    ) vuln = TRUE;

    if(vuln)
    {
      num = key - ("SMB/Flash_Player/"+variant+"/Version/");
      file = files["SMB/Flash_Player/"+variant+"/File/"+num];
      if (variant == "Plugin")
      {
        info += '\n  Product           : Browser Plugin (for Firefox / Netscape / Opera)';
        fix = "22.0.0.192 / 18.0.0.360";
      }
      else if (variant == "ActiveX")
      {
        info += '\n  Product           : ActiveX control (for Internet Explorer)';
        fix = "22.0.0.192 / 18.0.0.360";
      }
      else if ("Chrome" >< variant)
      {
        info += '\n  Product           : Browser Plugin (for Google Chrome)';
        if(variant == "Chrome")
          fix = "Upgrade to a version of Google Chrome running Flash Player 22.0.0.192";
      }
      info += '\n  Path              : ' + file +
              '\n  Installed version : ' + ver;
      if (variant == "Chrome_Pepper")
        info += '\n  Fixed version     : 22.0.0.192 (Chrome PepperFlash)';
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
