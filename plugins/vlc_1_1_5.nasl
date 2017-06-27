#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50650);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2011/10/24 19:44:08 $");

  script_bugtraq_id(44909);
  script_osvdb_id(69288);
  script_xref(name:"Secunia", value:"42244");

  script_name(english:"VLC Media Player < 1.1.5 Buffer Overflow");
  script_summary(english:"Checks version of VLC");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a media player that allows arbitrary
code execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of VLC media player installed on the remote Windows host
is earlier than 1.1.5.  Such versions are vulnerable to a stack
smashing attack in the Samba network share access module due to an
error in the way VLC calls the Windows API function
'WNetAddConnection2A()' when opening 'smb://' URLs. 

If an attacker can trick a user into opening a specially crafted URL
with the affected application, he can leverage this issue to execute
arbitrary code subject to that user's permissions."
  );

  script_set_attribute(
    attribute:"see_also",
    value:"http://shinnai.altervista.org/exploits/SH-008-20101026.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.videolan.org/security/sa1006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.videolan.org/developers/vlc-branch/NEWS"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to VLC Media Player version 1.1.5 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/18");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_dependencies("vlc_installed.nasl");
  script_require_keys("SMB/VLC/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("SMB/VLC/Version");

# nb: 'version' may look like '0.9.8a'!
if (
  version =~ "^0\." ||
  version =~ "^1\.0\." ||
  version =~ "^1\.1\.[0-4]($|[^0-9])"
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
      '\n  Fixed version     : 1.1.5\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));

  exit(0);
}
else exit(0, "The host is not affected since VLC "+version+" is installed.");
