#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87244);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/04/28 18:33:26 $");

  script_cve_id(
    "CVE-2015-8045",
    "CVE-2015-8047",
    "CVE-2015-8048",
    "CVE-2015-8049",
    "CVE-2015-8050",
    "CVE-2015-8054",
    "CVE-2015-8055",
    "CVE-2015-8056",
    "CVE-2015-8057",
    "CVE-2015-8058",
    "CVE-2015-8059",
    "CVE-2015-8060",
    "CVE-2015-8061",
    "CVE-2015-8062",
    "CVE-2015-8063",
    "CVE-2015-8064",
    "CVE-2015-8065",
    "CVE-2015-8066",
    "CVE-2015-8067",
    "CVE-2015-8068",
    "CVE-2015-8069",
    "CVE-2015-8070",
    "CVE-2015-8071",
    "CVE-2015-8401",
    "CVE-2015-8402",
    "CVE-2015-8403",
    "CVE-2015-8404",
    "CVE-2015-8405",
    "CVE-2015-8406",
    "CVE-2015-8407",
    "CVE-2015-8408",
    "CVE-2015-8409",
    "CVE-2015-8410",
    "CVE-2015-8411",
    "CVE-2015-8412",
    "CVE-2015-8413",
    "CVE-2015-8414",
    "CVE-2015-8415",
    "CVE-2015-8416",
    "CVE-2015-8417",
    "CVE-2015-8418",
    "CVE-2015-8419",
    "CVE-2015-8420",
    "CVE-2015-8421",
    "CVE-2015-8422",
    "CVE-2015-8423",
    "CVE-2015-8424",
    "CVE-2015-8425",
    "CVE-2015-8426",
    "CVE-2015-8427",
    "CVE-2015-8428",
    "CVE-2015-8429",
    "CVE-2015-8430",
    "CVE-2015-8431",
    "CVE-2015-8432",
    "CVE-2015-8433",
    "CVE-2015-8434",
    "CVE-2015-8435",
    "CVE-2015-8436",
    "CVE-2015-8437",
    "CVE-2015-8438",
    "CVE-2015-8439",
    "CVE-2015-8440",
    "CVE-2015-8441",
    "CVE-2015-8442",
    "CVE-2015-8443",
    "CVE-2015-8444",
    "CVE-2015-8445",
    "CVE-2015-8446",
    "CVE-2015-8447",
    "CVE-2015-8448",
    "CVE-2015-8449",
    "CVE-2015-8450",
    "CVE-2015-8451",
    "CVE-2015-8452",
    "CVE-2015-8453",
    "CVE-2015-8454",
    "CVE-2015-8455",
    "CVE-2015-8456",
    "CVE-2015-8457",
    "CVE-2015-8652",
    "CVE-2015-8653",
    "CVE-2015-8654",
    "CVE-2015-8655",
    "CVE-2015-8656",
    "CVE-2015-8657",
    "CVE-2015-8658",
    "CVE-2015-8820",
    "CVE-2015-8821",
    "CVE-2015-8822"
  );
  script_bugtraq_id(
    78710,
    78712,
    78713,
    78714,
    78715,
    78716,
    78717,
    78718,
    78802
  );
  script_osvdb_id(
    131208,
    131209,
    131210,
    131211,
    131212,
    131213,
    131214,
    131215,
    131216,
    131217,
    131218,
    131219,
    131220,
    131221,
    131222,
    131223,
    131224,
    131225,
    131226,
    131227,
    131228,
    131229,
    131230,
    131231,
    131232,
    131233,
    131234,
    131235,
    131236,
    131237,
    131238,
    131239,
    131240,
    131241,
    131242,
    131243,
    131244,
    131245,
    131246,
    131247,
    131248,
    131249,
    131250,
    131251,
    131252,
    131253,
    131254,
    131255,
    131256,
    131257,
    131258,
    131259,
    131260,
    131261,
    131262,
    131463,
    131264,
    131265,
    131266,
    131267,
    131268,
    131269,
    131270,
    131271,
    131272,
    131273,
    131274,
    131275,
    131276,
    131277,
    131278,
    131279,
    131280,
    131281,
    131282,
    131283,
    131464,
    131465,
    131466,
    131467,
    135374,
    135375,
    135376,
    135377,
    135378,
    135379,
    135380,
    135381,
    135382,
    135383
  );
  script_xref(name:"ZDI", value:"ZDI-15-601");
  script_xref(name:"ZDI", value:"ZDI-15-602");
  script_xref(name:"ZDI", value:"ZDI-15-603");
  script_xref(name:"ZDI", value:"ZDI-15-604");
  script_xref(name:"ZDI", value:"ZDI-15-605");
  script_xref(name:"ZDI", value:"ZDI-15-606");
  script_xref(name:"ZDI", value:"ZDI-15-607");
  script_xref(name:"ZDI", value:"ZDI-15-608");
  script_xref(name:"ZDI", value:"ZDI-15-609");
  script_xref(name:"ZDI", value:"ZDI-15-610");
  script_xref(name:"ZDI", value:"ZDI-15-611");
  script_xref(name:"ZDI", value:"ZDI-15-612");
  script_xref(name:"ZDI", value:"ZDI-15-613");
  script_xref(name:"ZDI", value:"ZDI-15-614");
  script_xref(name:"ZDI", value:"ZDI-15-655");
  script_xref(name:"ZDI", value:"ZDI-15-656");
  script_xref(name:"ZDI", value:"ZDI-15-657");
  script_xref(name:"ZDI", value:"ZDI-15-658");
  script_xref(name:"ZDI", value:"ZDI-15-659");
  script_xref(name:"ZDI", value:"ZDI-15-660");
  script_xref(name:"ZDI", value:"ZDI-15-661");
  script_xref(name:"ZDI", value:"ZDI-15-662");
  script_xref(name:"ZDI", value:"ZDI-15-663");
  script_xref(name:"ZDI", value:"ZDI-15-664");
  script_xref(name:"EDB-ID", value:"39042");
  script_xref(name:"EDB-ID", value:"39043");
  script_xref(name:"EDB-ID", value:"39047");
  script_xref(name:"EDB-ID", value:"39049");
  script_xref(name:"EDB-ID", value:"39051");
  script_xref(name:"EDB-ID", value:"39052");
  script_xref(name:"EDB-ID", value:"39053");
  script_xref(name:"EDB-ID", value:"39054");
  script_xref(name:"EDB-ID", value:"39072");

  script_name(english:"Adobe Flash Player <= 19.0.0.245 Multiple Vulnerabilities (APSB15-32)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Windows host
is equal or prior to version 19.0.0.245. It is, therefore, affected by
multiple vulnerabilities :

  - Multiple heap buffer overflow conditions exist that
    allow an attacker to execute arbitrary code.
    (CVE-2015-8438, CVE-2015-8446)

  - Multiple memory corruption issues exist that allow an
    attacker to execute arbitrary code. (CVE-2015-8045,
    CVE-2015-8047, CVE-2015-8060, CVE-2015-8408,
    CVE-2015-8416, CVE-2015-8417, CVE-2015-8418,
    CVE-2015-8419, CVE-2015-8443, CVE-2015-8444,
    CVE-2015-8451, CVE-2015-8455, CVE-2015-8652,
    CVE-2015-8654, CVE-2015-8656, CVE-2015-8657,
    CVE-2015-8658, CVE-2015-8820)

  - Multiple security bypass vulnerabilities exist that
    allow an attacker to write arbitrary data to the file
    system under user permissions. (CVE-2015-8453,
    CVE-2015-8440,  CVE-2015-8409)

  - A stack buffer overflow condition exists that allows an
    attacker to execute arbitrary code. (CVE-2015-8407,
    CVE-2015-8457)

  - A type confusion error exists that allows an attacker to
    execute arbitrary code. (CVE-2015-8439, CVE-2015-8456)

  - An integer overflow condition exists that allows an
    attacker to execute arbitrary code. (CVE-2015-8445)

  - A buffer overflow condition exists that allows an
    attacker to execute arbitrary code. (CVE-2015-8415)

  - Multiple use-after-free errors exist that allow an
    attacker to execute arbitrary code. (CVE-2015-8048,
    CVE-2015-8049, CVE-2015-8050, CVE-2015-8055,
    CVE-2015-8056, CVE-2015-8057, CVE-2015-8058,
    CVE-2015-8059, CVE-2015-8061, CVE-2015-8062,
    CVE-2015-8063, CVE-2015-8064, CVE-2015-8065,
    CVE-2015-8066, CVE-2015-8067, CVE-2015-8068,
    CVE-2015-8069, CVE-2015-8070, CVE-2015-8071,
    CVE-2015-8401, CVE-2015-8402, CVE-2015-8403,
    CVE-2015-8404, CVE-2015-8405, CVE-2015-8406,
    CVE-2015-8410, CVE-2015-8411, CVE-2015-8412,
    CVE-2015-8413, CVE-2015-8414, CVE-2015-8420,
    CVE-2015-8421, CVE-2015-8422, CVE-2015-8423,
    CVE-2015-8424, CVE-2015-8425, CVE-2015-8426,
    CVE-2015-8427, CVE-2015-8428, CVE-2015-8429,
    CVE-2015-8430, CVE-2015-8431, CVE-2015-8432,
    CVE-2015-8433, CVE-2015-8434, CVE-2015-8435,
    CVE-2015-8436, CVE-2015-8437, CVE-2015-8441,
    CVE-2015-8442, CVE-2015-8447, CVE-2015-8448,
    CVE-2015-8449, CVE-2015-8450, CVE-2015-8452,
    CVE-2015-8454, CVE-2015-8653, CVE-2015-8655,
    CVE-2015-8821, CVE-2015-8822");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-32.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 20.0.0.228 or later.

Alternatively, Adobe has made version 18.0.0.268 available for those
installations that cannot be upgraded to the latest version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

    # Chrome Flash <= 19.0.0.245
    if(variant == "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"19.0.0.245",strict:FALSE) <= 0
    ) vuln = TRUE;

    # <= 18.0.0.261 
    if(variant != "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"18.0.0.261",strict:FALSE) <= 0
    ) vuln = TRUE;

    # 19 <= 19.0.0.245
    if(variant != "Chrome_Pepper" &&
       ver =~ "^(?:19|[2-9]\d)\." &&
       ver_compare(ver:ver,fix:"19.0.0.245",strict:FALSE) <= 0
    ) vuln = TRUE;

    if(vuln)
    {
      num = key - ("SMB/Flash_Player/"+variant+"/Version/");
      file = files["SMB/Flash_Player/"+variant+"/File/"+num];
      if (variant == "Plugin")
      {
        info += '\n  Product           : Browser Plugin (for Firefox / Netscape / Opera)';
        fix = "20.0.0.228 / 18.0.0.268";
      }
      else if (variant == "ActiveX")
      {
        info += '\n  Product           : ActiveX control (for Internet Explorer)';
        fix = "20.0.0.228 / 18.0.0.268";
      }
      else if ("Chrome" >< variant)
      {
        info += '\n  Product           : Browser Plugin (for Google Chrome)';
        if(variant == "Chrome")
          fix = "Upgrade to a version of Google Chrome running Flash Player 20.0.0.228";
      }
      info += '\n  Path              : ' + file +
              '\n  Installed version : ' + ver;
      if (variant == "Chrome_Pepper")
        info += '\n  Fixed version     : 20.0.0.228 (Chrome PepperFlash)';
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
