#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63381);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/07/08 10:41:12 $");

  script_cve_id("CVE-2013-1868");
  script_bugtraq_id(57079);
  script_osvdb_id(88299, 88813);

  script_name(english:"VLC < 2.0.5 Multiple Vulnerabilities");
  script_summary(english:"Checks version of VLC");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a media player that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of VLC media player installed on the remote host is earlier
than 2.0.5.  It is, therefore, reportedly affected by the following
vulnerabilities :

  - An error exists in the file 'modules/codec/subsdec.c'
    ('libsubsdec_plugin.dll') that does not properly
    validate input and can allow a buffer overflow. Opening
    a specially crafted file can result in the execution of
    arbitrary code. Note that the subtitles feature must be
    enabled for successful exploitation.

  - An error exists related to the 'freetype' renderer that
    does not properly validate input and can allow a buffer
    overflow. Opening a specially crafted file can result in
    the execution of arbitrary code.

  - Unspecified errors exist related to 'libaiff_plugin.dll'
    and to the 'SWF' demuxer that have unspecified impact."
  );
  script_set_attribute(attribute:"see_also", value:"http://securitytracker.com/id/1027929");
  script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/security/sa1301.html");
  # http://git.videolan.org/?p=vlc/vlc-2.0.git;a=commitdiff;h=8e8b02ff1720eb46dabe2864e79d47b40a2792d5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4cd2e15e");
  script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/vlc/releases/2.0.5.html");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to VLC version 2.0.5 or later.  Alternatively, remove any
affected plugin files from VLC's plugins directory."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/04");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("vlc_installed.nasl");
  script_require_keys("SMB/VLC/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

vuln_plugins_installed = make_list();
version = get_kb_item_or_exit("SMB/VLC/Version");

path = get_kb_item_or_exit("SMB/VLC/File");
path = ereg_replace(pattern:"^(.+)\\[^\\]+$", replace:"\1", string:path);

# nb: 'version' may look like '0.9.8a'!
if (
  version =~ "^[01]\." ||
  version =~ "^2\.0\.[0-4]($|[^0-9])"
) version_is_vulnerable = TRUE;
else audit(AUDIT_INST_PATH_NOT_VULN, "VLC", version, path);

installed_plugins = get_kb_list("SMB/VLC/plugin*");
if (isnull(installed_plugins)) audit(AUDIT_KB_MISSING, "SMB/VLC/plugin");

foreach plugin (installed_plugins)
  if (
    "\libsubsdec_plugin.dll" >< plugin ||
    "\libaiff_plugin.dll" >< plugin
  ) vuln_plugins_installed = make_list(vuln_plugins_installed, plugin);

if (
  # Paranoid scan
  report_paranoia > 1
  ||
  # plugin file check
  max_index(vuln_plugins_installed) > 0
)
{
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.0.5\n';

    # Add plugin paths if available
    if (max_index(vuln_plugins_installed) > 0)
    {
      report +=
      '\n  - Vulnerable Plugin(s) ';

      if (max_index(vuln_plugins_installed) > 1)
        report += 'Paths : ';
      else
        report += 'Path  : ';

      foreach plugin_path (vuln_plugins_installed)
        report += '\n    ' + plugin_path;

      report += '\n';
    }
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The VLC "+version+" install under "+path+" does not have the affected plugins.");
