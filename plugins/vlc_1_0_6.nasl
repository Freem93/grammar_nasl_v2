#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(48760);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/15 19:41:08 $");

  script_cve_id(
    "CVE-2010-1441",
    "CVE-2010-1442",
    "CVE-2010-1443",
    "CVE-2010-1444",
    "CVE-2010-1445"
  );
  script_bugtraq_id(39620, 41398);
  script_osvdb_id(
    63980,
    63981,
    63982,
    63983,
    63984,
    63985,
    63986,
    63987,
    63988,
    67109,
    74733,
    74734,
    74735,
    74736,
    74737
  );

  script_name(english:"VLC Media Player < 1.0.6 Multiple Vulnerabilities");
  script_summary(english:"Checks version of VLC");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains an application that suffers from
multiple vulnerabilities."
  );

  script_set_attribute(
    attribute:"description",
    value:
"The version of VLC media player installed on the remote host is
earlier than 1.0.6.  Such versions are affected by multiple
vulnerabilities :

  - A stack-based buffer overflow when handling M3U files
    with a ftp:// URI handler.

  - Heap-based buffer overflow vulnerabilities exist in the
    A/52, DTS, MPEG Audio decoders.

  - Invalid memory access vulnerabilities exist in the AVI,
    ASF, Matroska (MKV) demuxers, the XSPF playlist parser,
    and the ZIP archive decompressor.

  - A heap-based buffer overflow vulnerability exists in
    RTMP access.

If an attacker can trick a user into opening a specially crafted file
with the affected application, arbitrary code could be executed
subject to the user's privileges." );

  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2010/Jul/29"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.videolan.org/security/sa1003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.videolan.org/developers/vlc-branch/NEWS"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to VLC Media Player version 1.1.0 or later.

Note that the VLC developers have not released a pre-built version
1.0.6 for Windows so users are advised to upgrade to the next
available version."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/26");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("vlc_installed.nasl");
  script_require_keys("SMB/VLC/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("SMB/VLC/Version");

# nb: 'version' may look like '0.9.8a'!
if (version =~ "^(0\.|1\.0\.[0-5]($|[^0-9]))")
{
  if (report_verbosity > 0)
  {
    path = get_kb_item("SMB/VLC/File");
    if (isnull(path)) path = "n/a";
    else path = ereg_replace(pattern:"^(.+)\\[^\\]+$", replace:"\1", string:path);

    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.0.6\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));

  exit(0);
}
else exit(0, "The host is not affected since VLC "+version+" is installed.");
