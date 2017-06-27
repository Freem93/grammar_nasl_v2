#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(59173);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2012/12/22 03:33:37 $");

  script_cve_id("CVE-2012-1904", "CVE-2012-2406", "CVE-2012-2411");
  script_bugtraq_id(52706, 53555);
  script_osvdb_id(80529, 81943, 81944);
  script_xref(name:"EDB-ID", value:"18661");

  script_name(english:"RealPlayer for Windows < 15.0.4.53 Multiple Vulnerabilities");
  script_summary(english:"Checks RealPlayer build number.");

  script_set_attribute(attribute:"synopsis", value:
"A multimedia application on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its build number, the installed version of RealPlayer on
the remote Windows host is earlier than 15.0.4.53.  As such, it is
affected by multiple vulnerabilities :

  - A memory corruption error exists related to the
    handling of 'MP4' files. (CVE-2012-1904)

  - An unspecified error exists related to the parsing of
    'RealMedia ASMRuleBook' files that can lead to remote
    arbitrary code execution. (CVE-2012-2406)

  - A buffer overflow exists related to the parsing of
    'RealJukebox Media' content. (CVE-2012-2411)");
  # http://packetstormsecurity.org/files/111162/RealPlayer-1.1.4-Memory-Corruption.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a70d3491");
  script_set_attribute(attribute:"see_also", value:"http://service.real.com/realplayer/security/05152012_player/en/");
  script_set_attribute(attribute:"solution", value:"Upgrade to RealPlayer 15.0.4.53 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/17");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:realnetworks:realplayer");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("realplayer_detect.nasl");
  script_require_keys("SMB/RealPlayer/Product", "SMB/RealPlayer/Build");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");

prod = get_kb_item_or_exit("SMB/RealPlayer/Product");
build = get_kb_item_or_exit("SMB/RealPlayer/Build");
path = get_kb_item("SMB/RealPlayer/Path");
version = get_kb_item("SMB/RealPlayer/Version");

vuln = FALSE;
if ("RealPlayer" == prod)
{
  if (ver_compare(ver:build, fix:'15.0.4.53') == -1) vuln = TRUE;
}
else if ("RealPlayer SP" == prod)
{
  # Check for all versions of RealPlayer SP up to and including 12.0.0.879 (version 1.1.5)
  if (build =~ '^12\\.0\\.0\\..*' && ver_compare(ver:build, fix:'12.0.0.879') <= 0) vuln = TRUE;
}
else audit(AUDIT_NOT_INST, "RealPlayer / RealPlayer SP");

if (vuln)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Product           : ' + prod +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + 
      '\n  Installed build   : ' + build +
      '\n  Fixed version     : RealPlayer 15.0.4.53\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "RealPlayer", version, path);
