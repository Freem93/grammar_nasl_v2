#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71772);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 14:22:07 $");

  script_cve_id("CVE-2013-6877", "CVE-2013-7260");
  script_bugtraq_id(64398, 64695);
  script_osvdb_id(101135, 101356);
  script_xref(name:"CERT", value:"698278");
  script_xref(name:"EDB-ID", value:"30468");

  script_name(english:"RealPlayer for Windows < 17.0.4.61 RMP Buffer Overflow");
  script_summary(english:"Checks RealPlayer build number");

  script_set_attribute(attribute:"synopsis", value:
"A multimedia application on the remote Windows host is affected by a
buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its build number, the installed version of RealPlayer on
the remote Windows host is earlier than 17.0.4.61.  It is, therefore,
affected by a buffer overflow vulnerability when handling the
'encoding', 'trackid', and 'version' attributes in RealPlayer Metadata
Package (RMP) files that could lead to arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Dec/150");
  script_set_attribute(attribute:"see_also", value:"http://service.real.com/realplayer/security/12202013_player/en/");
  script_set_attribute(attribute:"solution", value:"Upgrade to RealPlayer Cloud 17.0.4.61 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'RealNetworks RealPlayer Version Attribute Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/31");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:realnetworks:realplayer");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

if ("RealPlayer" != prod) audit(AUDIT_NOT_INST, "RealPlayer");

cutoff_version = '17.0.2.206';

if (ver_compare(ver:build, fix:cutoff_version) <= 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Product           : ' + prod +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Installed build   : ' + build +
      '\n  Fixed version     : 17.0.4.61\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "RealPlayer", version, path);
