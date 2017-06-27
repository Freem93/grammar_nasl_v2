#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(53409);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/02 14:37:09 $");

  script_cve_id("CVE-2011-1426", "CVE-2011-1525");
  script_bugtraq_id(46946, 47335);
  script_osvdb_id(71260, 73158);
  script_xref(name:"EDB-ID", value:"17019");
  script_xref(name:"Secunia", value:"43847");

  script_name(english:"RealPlayer for Windows < Build 12.0.1.647 Multiple Vulnerabilities");
  script_summary(english:"Checks RealPlayer build number.");

  script_set_attribute(attribute:"synopsis", value:
"A multimedia application on the remote Windows host is affected by
multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"According to its build number, the installed version of RealPlayer on
the remote Windows host is affected by multiple vulnerabilities :

  - The OpenURLInDefaultBrowser() method will open and
    execute the first parameter based on the operating
    system's default handler for the filetype and is
    accessible through RealPlayer's internal browser, which
    in turn can be reached using a specially crafted
    RealPlayer audio or settings (RNX) file. (CVE-2011-1426)

  - A heap-based buffer overflow vulnerability can be
    triggered when processing a malformed Internet Video
    Recording (IVR) file. (CVE-2011-1525)");

  script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/real_5-adv.txt");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Mar/189");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-122/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Apr/117");
  script_set_attribute(attribute:"see_also", value:"http://service.real.com/realplayer/security/04122011_player/en/");
  script_set_attribute(attribute:"solution", value:"Upgrade to RealPlayer 14.0.3.647 (Build 12.0.1.647) or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/14");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:realnetworks:realplayer");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("realplayer_detect.nasl");
  script_require_keys("SMB/RealPlayer/Product", "SMB/RealPlayer/Build");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

prod = get_kb_item_or_exit("SMB/RealPlayer/Product");
build = get_kb_item_or_exit("SMB/RealPlayer/Build");
path = get_kb_item("SMB/RealPlayer/Path");
version = get_kb_item("SMB/RealPlayer/Version");

vuln = FALSE;
if ("RealPlayer" == prod)
{
  if (ver_compare(ver:build, fix:'12.0.1.647') == -1) vuln = TRUE;
}
else if ("RealPlayer SP" == prod)
{
  # Check for all versions of RealPlayer SP up to and including 12.0.0.879 (version 1.1.5)
  if (build =~ '^12\\.0\\.0\\..*' && ver_compare(ver:build, fix:'12.0.0.879') <= 0) vuln = TRUE;
}
else exit(0, 'Neither RealPlayer nor RealPlayer SP was detected on the remote host.');

if (vuln)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Product           : ' + prod +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + 
      '\n  Installed build   : ' + build +
      '\n  Fix               : RealPlayer Build 12.0.1.647\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, 'The host is not affected because '+prod+' build '+build+' is installed.');
