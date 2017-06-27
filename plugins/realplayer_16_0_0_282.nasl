#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63289);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/09 20:54:57 $");

  script_cve_id("CVE-2012-5690", "CVE-2012-5691");
  script_bugtraq_id(56956);
  script_osvdb_id(88486, 88487);

  script_name(english:"RealPlayer for Windows < 16.0.0.282 Multiple Vulnerabilities");
  script_summary(english:"Checks RealPlayer build number.");

  script_set_attribute(attribute:"synopsis", value:
"A multimedia application on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its build number, the installed version of RealPlayer on
the remote Windows host is earlier than 16.0.0.282.  It is, therefore,
affected by multiple vulnerabilities :

  - An error exists related to 'RealAudio' handling and
    invalid pointers that can allow arbitrary code
    execution. (CVE-2012-5690)

  - An error exists related to 'RealMedia' handling that
    can allow a buffer overflow leading to arbitrary code
    execution. (CVE-2012-5691)"
  );
  script_set_attribute(attribute:"see_also", value:"http://service.real.com/realplayer/security/12142012_player/en/");
  script_set_attribute(attribute:"solution", value:"Upgrade to RealPlayer 16.0.0.282 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-13-026");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'RealPlayer RealMedia File Handling Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/18");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:realnetworks:realplayer");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("realplayer_detect.nasl");
  script_require_keys("SMB/RealPlayer/Product", "SMB/RealPlayer/Build");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

prod = get_kb_item_or_exit("SMB/RealPlayer/Product");
build = get_kb_item_or_exit("SMB/RealPlayer/Build");
path = get_kb_item("SMB/RealPlayer/Path");
version = get_kb_item("SMB/RealPlayer/Version");

vuln = FALSE;
if ("RealPlayer" == prod)
{
  if (ver_compare(ver:build, fix:'16.0.0.282') == -1) vuln = TRUE;
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
      '\n  Fixed version     : RealPlayer 16.0.0.282\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "RealPlayer", version, path);
