#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63137);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/11/07 11:40:08 $");

  script_cve_id("CVE-2012-0023");
  script_bugtraq_id(51231);
  script_osvdb_id(77975);

  script_name(english:"VLC get_chunk_header Function TiVo File Remote Code Execution");
  script_summary(english:"Checks version of VLC");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a media player that is affected by a
code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of VLC installed on the remote host is 0.x later than 0.9.0
or 1.x earlier than or equal to 1.1.12.  It, therefore, contains a
double-free error in the function 'get_chunk_header' in the file
'modules/demux/ty.c'.  This error can be exploited by a specially
crafted TiVo (TY) file, which could lead to remote arbitrary code
execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/security/sa1108.html");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to VLC version 1.1.13 / 2.0.0 or later.  Alternatively, remove
any affected plugin files from VLC's plugins directory."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/03");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("vlc_installed.nasl");
  script_require_keys("SMB/VLC/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/VLC/Version");

# nb: 'version' may look like '0.9.8a'!
# Affected:
# 0.9.0 - 1.1.12
if (
  version =~ "^(0\.9|0\.[1-9][0-9])($|[^0-9])" ||
  version =~ "^1\.0($|[^0-9])" ||
  version =~ "^1\.1\.([0-9]|1[0-2])($|[^0-9])"
)
{
  vuln_plugins_installed = make_list();

  installed_plugins = get_kb_list("SMB/VLC/plugin*");
  if (!isnull(installed_plugins))
    foreach plugin (installed_plugins)
      if ("\libty_plugin.dll" >< plugin)
        vuln_plugins_installed = make_list(vuln_plugins_installed, plugin);

  if (
    # Paranoid scan
    report_paranoia > 1
    ||
    # Or non-paranoid scan and plugin file check
    max_index(vuln_plugins_installed) > 0
  )
  {
    if (report_verbosity > 0)
    {
      path = get_kb_item("SMB/VLC/Path");
      if (isnull(path)) path = "n/a";

      report =
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 1.1.13 / 2.0.0\n';

      # Add plugin paths if available
      if (max_index(vuln_plugins_installed) > 0)
      {
        report +=
        '\n  Component         : ';

        if (max_index(vuln_plugins_installed) > 1)
          report += 'Vulnerable plugins';
        else
          report += 'Vulnerable plugin';

        foreach plugin_path (vuln_plugins_installed)
          report += '\n  File              : ' + plugin_path;

        report += '\n';
      }
      security_hole(port:get_kb_item("SMB/transport"), extra:report);
    }
    else security_hole(get_kb_item("SMB/transport"));
    exit(0);
  } else audit(AUDIT_NOT_INST, "The VLC plugin libty_plugin.dll");
}
else audit(AUDIT_INST_VER_NOT_VULN, "VLC", version);
