#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(60049);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/11/07 11:40:08 $");

  script_cve_id("CVE-2012-3377");
  script_bugtraq_id(54345);
  script_osvdb_id(83615);

  script_name(english:"VLC Media Player < 2.0.2 Ogg_DecodePacket Function OGG File Handling Overflow");
  script_summary(english:"Checks version of VLC");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a media player that is affected by a
buffer overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of VLC media player installed on the remote host is
earlier than 2.0.2.  It is, therefore, reportedly affected by a heap-
based buffer overflow vulnerability. 

An error exists in the function 'Ogg_DecodePacket' in the file
'modules/demux/ogg.c' that does not properly validate input and
could allow a heap-based buffer overflow. Opening a specially
crafted file can result in the execution of arbitrary code."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/vlc/releases/2.0.2.html");
  script_set_attribute(attribute:"see_also", value:"http://www.openwall.com/lists/oss-security/2012/07/06/2");
  # http://git.videolan.org/?p=vlc/vlc-2.0.git;a=commitdiff;h=16e9e126333fb7acb47d363366fee3deadc8331e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7fd6c9da");
  script_set_attribute(attribute:"see_also", value:"http://www.securitytracker.com/id?1027224");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to VLC Media Player version 2.0.2 or later.  Alternatively,
remove any affected plugin files from VLC's plugins directory."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/19");

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

vuln_plugins_installed = make_list();
version = get_kb_item_or_exit("SMB/VLC/Version");

# nb: 'version' may look like '0.9.8a'!
if (
  version =~ "^[01]\." ||
  version =~ "^2\.0\.[01]($|[^0-9])"
) version_is_vulnerable = TRUE;
else audit(AUDIT_INST_VER_NOT_VULN, "VLC", version);

installed_plugins = get_kb_list("SMB/VLC/plugin*");
if (isnull(installed_plugins)) audit(AUDIT_KB_MISSING, "SMB/VLC/plugin");

foreach plugin (installed_plugins)
  if ("\libogg_plugin.dll" >< plugin)
    vuln_plugins_installed = make_list(vuln_plugins_installed, plugin);

if (
  # Paranoid scan
  report_paranoia > 1
  ||
  # Or non-paranoid scan and plugin file check
  (
    report_paranoia <= 1 &&
    max_index(vuln_plugins_installed) > 0
  )
)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item("SMB/VLC/File");
    if (isnull(path)) path = "n/a";
    else path = ereg_replace(pattern:"^(.+)\\[^\\]+$", replace:"\1", string:path);

    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.0.2\n';

    # Add plugin paths if available
    if (max_index(vuln_plugins_installed) > 0)
    {
      report += 
      '\n  - Vulnerable Plugin ';

      if (max_index(vuln_plugins_installed) > 1)
        report += 'Paths : ';
      else
        report += 'Path  : ';

      foreach plugin_path (vuln_plugins_installed)
        report += '\n    ' + plugin_path;

      report += '\n';
    }

    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));

  exit(0);
}
else exit(0, "The VLC "+version+" install does not have the affected plugins.");
