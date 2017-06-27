#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55608);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/11/07 11:40:08 $");

  script_cve_id("CVE-2011-2587", "CVE-2011-2588");
  script_bugtraq_id(48664);
  script_osvdb_id(74056, 74057);
  script_xref(name:"Secunia", value:"45066");

  script_name(english:"VLC Media Player 0.5.0 to 1.1.10 Multiple Buffer Overflows");
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
"The version of VLC media player installed on the remote host is
between 0.5.0 and 1.1.10.  As such, it is reportedly affected by
multiple vulnerabilities:

  - An integer overflow error exists in the handling of
    the RealAudio portions of RealMedia files. 
    (VideoLAN-SA-1105)

  - An integer underflow error exists in the handling of
    'strf' portions of AVI files. (VideoLAN-SA-1106)

Exploiting these vulnerabilities can lead to application crashes and
possibly code execution through heap-based buffer overflows.");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.videolan.org/security/sa1105.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.videolan.org/security/sa1106.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to VLC Media Player version 1.1.11 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/18");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

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
# 0.5.0 >= 1.1.10 are affected
if (
  (ver[0] == 0 && ver[1] >= 5) || 
  (
    ver[0] == 1 && 
    (
      (ver[1] < 1) ||
      (ver[1] == 1 && ver[2] < 11)
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
      '\n  Fixed version     : 1.1.11\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));

  exit(0);
}
else exit(0, "The host is not affected since VLC "+version+" is installed.");
