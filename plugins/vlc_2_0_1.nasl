#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58416);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/19 18:10:50 $");

  script_cve_id("CVE-2012-1775", "CVE-2012-1776");
  script_bugtraq_id(52550, 53391);
  script_osvdb_id(80188, 80189);
  script_xref(name:"EDB-ID", value:"18825");

  script_name(english:"VLC Media Player < 2.0.1 Multiple Vulnerabilities");
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
"The version of VLC media player installed on the remote host is
earlier than 2.0.1.  Such versions are affected by multiple
vulnerabilities:

  - The function 'MMSOpen' in the MMS access plugin
    contains a boundary error that can allow a stack-based
    buffer overflow when maliciously crafted MMS streams
    are opened. (CVE-2012-1775)

  - The Realrtsp plugin contains an unspecified error that
    can allow a heap-based buffer overflow when maliciously
    crafted Real rtsp streams are opened. (CVE-2012-1776)"
  );
  # http://xorl.wordpress.com/2012/05/16/cve-2012-1775-vlc-mms-support-stack-overflow/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f84212cb"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.videolan.org/security/sa1201.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.videolan.org/security/sa1202.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.videolan.org/vlc/releases/2.0.1.html"
  );
  # Include a list of the patches that aren't
  # going out as new, fixed releases; just 
  # patches.
  # git diff for 1.2.x RealRTSP fix
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d62cd2cc"
  );
  # git diff for 1.2.x MMS fix
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6d1dc580"
  );
  # git diff for 1.1.x RealRTSP fix
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?22cac0f0"
  );
  # git diff for 1.1.x MMS fix
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dbc08f65"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to VLC Media Player version 2.0.1 or later.  Alternatively,
remove any affected plugin files from VLC's plugins directory."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'VLC MMS Stream Handling Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/21");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("vlc_installed.nasl");
  script_require_keys("SMB/VLC/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

vuln_plugins_installed = make_list();
version = get_kb_item_or_exit("SMB/VLC/Version");

# nb: 'version' may look like '0.9.8a'!
if (
  version =~ "^[01]\." ||
  version =~ "^2\.0\.0($|[^0-9])"
) version_is_vulnerable = TRUE;
else exit(0, "The VLC "+version+" install is not affected.");

installed_plugins = get_kb_list("SMB/VLC/plugin*");
if (isnull(installed_plugins)) exit(0, "Unable to obtain VLC plugin list from KB.");

foreach plugin (installed_plugins)
  if ("\libaccess_mms_plugin.dll" >< plugin || "\libaccess_realrtsp_plugin.dll" >< plugin)
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
      '\n  Fixed version     : 2.0.1\n';

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
