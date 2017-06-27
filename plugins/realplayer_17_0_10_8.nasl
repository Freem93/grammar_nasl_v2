#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76458);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/19 17:53:35 $");

  script_cve_id("CVE-2014-3113");
  script_bugtraq_id(68442);
  script_osvdb_id(108615);
  script_xref(name:"IAVA", value:"2014-A-0097");

  script_name(english:"RealPlayer for Windows <= 17.0.8.22 MP4 Multiple Memory Corruptions");
  script_summary(english:"Checks RealPlayer version.");

  script_set_attribute(attribute:"synopsis", value:
"A multimedia application on the remote Windows host is affected by
multiple memory corruption vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its build number, the installed version of RealPlayer on
the remote Windows host is prior to or equal to 17.0.8.22. It is,
therefore, affected by multiple memory corruption vulnerabilities.
These vulnerabilities allow remote attackers to execute arbitrary code
within the context of the running application via a malformed 'elst'
or 'stsz' atom in a specially crafted MP4 file.");
  script_set_attribute(attribute:"see_also", value:"http://service.real.com/realplayer/security/06272014_player/en/");
  # http://www.fortiguard.com/advisory/RealNetworks-RealPlayer-Memory-Corruption/
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?c4b56f7b");
  script_set_attribute(attribute:"solution", value:"Upgrade to RealPlayer 17.0.10.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:realnetworks:realplayer");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

cutoff_version = '17.0.8.22';
fixed_version = '17.0.10.8';

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
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "RealPlayer", version, path);
