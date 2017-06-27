#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(48906);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/03/10 16:46:29 $");

  script_cve_id("CVE-2010-3124");
  script_bugtraq_id(42707);
  script_osvdb_id(67492);
  script_xref(name:"EDB-ID", value:"14750");

  script_name(english:"VLC Media Player < 1.1.4 Path Subversion Arbitrary DLL Injection Code Execution");
  script_summary(english:"Checks version of VLC");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains an application that allows arbitrary
code execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of VLC media player installed on the remote host is
earlier than 1.1.4.  Such versions insecurely look in their current
working directory when resolving DLL dependencies, such as for
'wintab32.dll'. 

If a malicious DLL with the same name as a required DLL is located in
the application's current working directory, the malicious DLL will be
loaded."
  );

  script_set_attribute(
    attribute:"see_also",
    value:"http://msdn.microsoft.com/en-us/library/ff919712(VS.85).aspx"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.acrossecurity.com/aspr/ASPR-2010-08-18-1-PUB.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://blog.rapid7.com/?p=5325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.videolan.org/security/sa1005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.videolan.org/developers/vlc-branch/NEWS"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to VLC Media Player version 1.1.4 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/27");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

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
  version =~ "^1\.1\.[0-3]($|[^0-9])"
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
      '\n  Fixed version     : 1.1.4\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));

  exit(0);
}
else exit(0, "The host is not affected since VLC "+version+" is installed.");
