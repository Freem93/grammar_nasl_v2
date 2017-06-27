#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51851);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/11/07 11:40:08 $");

  script_cve_id("CVE-2011-0531");
  script_bugtraq_id(46060);
  script_osvdb_id(70698);

  script_name(english:"VLC Media Player < 1.1.7 MKV Input Validation Vulnerability");
  script_summary(english:"Checks version of VLC");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains an media player that is affected by
a code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of VLC media player installed on the remote host is
earlier than 1.1.7.  Such versions are reportedly affected by the
following vulnerability :

  - Insufficient input validation when parsing a specially
    crafted Matroska or WebM (MKV) file can be exploited to
    execute arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.videolan.org/security/sa1102.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.videolan.org/developers/vlc-branch/NEWS"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to VLC Media Player version 1.1.7 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'VideoLAN VLC MKV Memory Corruption');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
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

# nb: 'version' may look like '0.9.8a'!
if (
  version =~ "^0\." ||
  version =~ "^1\.0\." ||
  version =~ "^1\.1\.[0-6]($|[^0-9])"
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
      '\n  Fixed version     : 1.1.7\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));

  exit(0);
}
else exit(0, "The host is not affected since VLC "+version+" is installed.");
