#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55024);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2011/10/24 19:44:08 $");

  script_cve_id("CVE-2011-2194");
  script_bugtraq_id(48171);
  script_osvdb_id(73450);
  script_xref(name:"EDB-ID", value:"17372");
  script_xref(name:"Secunia", value:"44412");

  script_name(english:"VLC Media Player XSPF Playlist Integer Overflow");
  script_summary(english:"Checks version of VLC");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a media player that can allow code
execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of VLC media player installed on the remote host is 0.8.5
or later and is earlier than 1.1.10.  Such versions are affected by an
integer overflow vulnerability that can be exploited by tricking a
user into opening a crafted XSPF playlist file.  Exploiting this
vulnerability can lead to application crashes and possibly code
execution.");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.videolan.org/security/sa1104.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.videolan.org/vlc/releases/1.1.10.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to VLC Media Player version 1.1.10 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/09");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");

  script_dependencies("vlc_installed.nasl");
  script_require_keys("SMB/VLC/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/VLC/Version");

if (version =~ "^1(\.1)?$")
  exit(1, "The VLC version, "+version+" is not granular enough to make a determination");

ver = split(version,sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

# nb: 'version' may look like '0.9.8a'!
# 0.8.5 >= 1.1.9 are affected
if (
  (
    ver[0] == 0 && 
    ( 
      (ver[1] == 8 && ver[2] >= 5) ||
      (ver[1] > 8)
    )
  )
  || 
  (
    ver[0] == 1 && 
    (
      (ver[1] < 1) ||
      (ver[1] == 1 && ver[2] < 10)
    )
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
      '\n  Fixed version     : 1.1.10\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));

  exit(0);
}
else exit(0, "The host is not affected since VLC "+version+" is installed.");
