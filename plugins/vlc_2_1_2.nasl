#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72279);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/19 18:10:50 $");

  script_cve_id("CVE-2013-6933", "CVE-2013-6934");
  script_bugtraq_id(65131, 65139);
  script_osvdb_id(102440);

  script_name(english:"VLC 2.x < 2.1.2 parseRTSPRequestString Function RTSP Command Parsing Overflow");
  script_summary(english:"Checks VLC version");

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
than 2.1.2.  As such, it reportedly includes a version of Live Networks'
Live555 Streaming Media library earlier than 2013.11.29.  A buffer
overflow vulnerability in the 'parseRTSPRequestString()' function in
that library exists that could lead to a program crash or arbitrary code
execution when handling a specially crafted RTSP message."
  );
  # http://isecpartners.github.io/fuzzing/vulnerabilities/2013/12/30/vlc-vulnerability.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?011ac987");
  script_set_attribute(attribute:"see_also", value:"http://www.live555.com/liveMedia/public/changelog.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("vlc_installed.nasl");
  script_require_keys("SMB/VLC/installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/VLC/installed");
app_name = "VLC Media Player";
version = get_kb_item_or_exit("SMB/VLC/Version");
path = get_kb_item_or_exit("SMB/VLC/Path");

# Version must be greater than 2.0 or not vuln. 
fix = "2.1.2";
if (version =~ "^2\..*$" && ver_compare(ver:version, fix: fix, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port:port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
