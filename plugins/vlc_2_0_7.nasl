#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69015);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/13 21:07:14 $");

  script_cve_id("CVE-2013-3564", "CVE-2013-3565", "CVE-2013-7340");
  script_bugtraq_id(60705, 66546);
  script_osvdb_id(94139, 94140, 94444, 104735);

  script_name(english:"VLC < 2.0.7 Multiple Vulnerabilities");
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
than 2.0.7 and is, therefore, affected by the following vulnerabilities:

  - The web interface contains a flaw that does not validate
    input passed via XML services resulting in a cross-site
    scripting vulnerability.

  - A flaw exists in the XML services of the web interface
    that may allow a remote attacker to execute media player
    commands.

  - A flaw exists that could lead to a denial of service / 
    memory consumption when loading a malicious playlist."
  );
  # http://blog.spiderlabs.com/2013/06/twsl2013-006-cross-site-scripting-vulnerability-in-coldbox.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f33883d");
  script_set_attribute(attribute:"see_also", value:"https://www.trustwave.com/spiderlabs/advisories/TWSL2013-007.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/vlc/releases/2.0.7.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to VLC version 2.0.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/23");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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

port = get_kb_item("SMB/transport");
if (!port) port = 445;

# nb: 'version' may look like '0.9.8a'!
if (
  version =~ "^[01]\." ||
  version =~ "^2\.0\.[0-6]($|[^0-9])"
)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.0.7\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "VLC", version, path);
