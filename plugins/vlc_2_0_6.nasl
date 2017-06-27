#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(66216);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/04/25 19:49:00 $");

  script_cve_id("CVE-2013-1954");
  script_bugtraq_id(57333);
  script_osvdb_id(89598);

  script_name(english:"VLC < 2.0.6 ASF Demuxer Buffer Overflow");
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
"The version of VLC media player installed on the remote host is earlier
than 2.0.6.  It is, therefore, reportedly affected by a buffer overflow
vulnerability related to the ASF demuxer plugin."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/security/sa1302.html");
  # http://git.videolan.org/?p=vlc.git;a=commit;h=b31ce523331aa3a6e620b68cdfe3f161d519631e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b8052708");
  script_set_attribute(attribute:"see_also", value:"http://trac.videolan.org/vlc/ticket/8024");
  script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/vlc/releases/2.0.6.html");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to VLC version 2.0.6 or later.  Alternatively, remove the
affected plugin file from VLC's plugins directory."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/25");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

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
  version =~ "^2\.0\.[0-5]($|[^0-9])"
) version_is_vulnerable = TRUE;
else audit(AUDIT_INST_PATH_NOT_VULN, "VLC", version, path);

installed_plugins = get_kb_list("SMB/VLC/plugin*");
if (isnull(installed_plugins)) audit(AUDIT_KB_MISSING, "SMB/VLC/plugin");

foreach plugin (installed_plugins)
  if ("\libasf_plugin.dll" >< plugin)
    vuln_plugins_installed = make_list(vuln_plugins_installed, plugin);

if (
  # Paranoid scan
  report_paranoia > 1
  ||
  # plugin file check
  max_index(vuln_plugins_installed) > 0
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.0.6\n';

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
else exit(0, "The VLC "+version+" install under "+path+" does not have the affected plugin.");
