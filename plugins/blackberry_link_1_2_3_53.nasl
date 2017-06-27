#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84987);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/07/27 13:18:16 $");

  script_cve_id("CVE-2015-4111");
  script_bugtraq_id(75950);
  script_osvdb_id(124762);

  script_name(english:"BlackBerry Link < 1.2.3.53 Codec Demux Arbitrary Code Execution");
  script_summary(english:"Checks version of BlackBerry Link.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has software installed that is affected by an
arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of BlackBerry Link installed that is
prior to version 1.2.3.53. Therefore, it is affected by an arbitrary
code execution vulnerability in the codec demux. A remote attacker can
exploit this, via crafted MP4 file, to execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://www.blackberry.com/btsc/KB37207");
  script_set_attribute(attribute:"see_also", value:"http://us.blackberry.com/software/desktop/blackberry-link.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to BlackBerry Link 1.2.3.53.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:blackberry:blackberry_link");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("blackberry_link_installed.nbin");
  script_require_keys("SMB/blackberry_link/Installed");
  script_require_ports(139, 445);
  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_hotfixes_fcheck.inc");

kb_base = "SMB/blackberry_link/";
appname = "BlackBerry Link";

path = get_kb_item_or_exit(kb_base + "Path");
version  = get_kb_item_or_exit(kb_base + "Version");

fix = "1.2.3.53";
report = NULL;

# Paranoid report is a straight version check, normal mode needs to check for the
# affected file as well to see if the workaround has been applied.

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{

  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);

port = get_kb_item('SMB/transport');
if (!port) port = 445;

# Paranoid - don't check for the workaround
if (report_paranoia > 1)
{
  if (report_verbosity > 0)
  {
    report += '\nNessus has not checked to see if the vendor-supplied' +
              '\nworkaround is in place.';

    security_hole(port:port, extra:report);
  }
  else
    security_hole(port:port);

  exit(0);
}

paths = make_list("BlackBerry Desktop", "BlackBerry Link");
parent_dir = path - "\BlackBerry Link";

foreach path(paths)
{
    if(hotfix_file_exists(path:parent_dir + path + "\Codecs\mc_demux_mp4_ds.ax"))
    {
      vuln = TRUE;
      break;
    }
  else
    continue;
}

if(vuln)
{
  if (report_verbosity > 0)
    security_hole(port:port, extra:report);
  else
    security_hole(port:port);

  exit(0);
}
else
{
  audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
}
