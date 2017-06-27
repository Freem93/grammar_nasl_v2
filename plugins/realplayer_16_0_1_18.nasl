#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65630);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/08/31 02:38:58 $");

  script_cve_id("CVE-2013-1750");
  script_bugtraq_id(58539);
  script_osvdb_id(91438);

  script_name(english:"RealPlayer for Windows < 16.0.1.18 MP4 Heap-Based Buffer Overflow");
  script_summary(english:"Checks RealPlayer build number.");

  script_set_attribute(attribute:"synopsis", value:
"A multimedia application on the remote Windows host is affected by a
buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its build number, the installed version of RealPlayer on
the remote Windows host is earlier than 16.0.1.18.  It is, therefore,
affected by a heap-based buffer overflow vulnerability related to
handling malformed MP4 files that could lead to arbitrary code
execution.");
  script_set_attribute(attribute:"see_also", value:"http://service.real.com/realplayer/security/03152013_player/en/");
  script_set_attribute(attribute:"solution", value:"Upgrade to RealPlayer 16.0.1.18 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/20");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:realnetworks:realplayer");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

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
  if (ver_compare(ver:build, fix:'16.0.1.18') < 0) vuln = TRUE;
}
else if ("RealPlayer SP" == prod)
{
  # Check for all versions of RealPlayer SP up to and including 12.0.0.879 (version 1.1.5)
  if (build =~ '^12\\.0\\.0\\..*' && ver_compare(ver:build, fix:'12.0.0.879') <= 0) vuln = TRUE;
}
else audit(AUDIT_NOT_INST, "RealPlayer / RealPlayer SP");

if (vuln)
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
      '\n  Fixed version     : RealPlayer 16.0.1.18\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "RealPlayer", version, path);
