#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51772);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/19 18:10:50 $");

  script_cve_id("CVE-2010-3907", "CVE-2011-0021", "CVE-2011-0522");
  script_bugtraq_id(45632, 45927, 46008);
  script_osvdb_id(70242, 70656, 72905, 72906);

  script_name(english:"VLC Media Player < 1.1.6 Multiple Vulnerabilities");
  script_summary(english:"Checks version of VLC");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains an media player that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of VLC media player installed on the remote host is
earlier than 1.1.6.  Such versions are reportedly affected by the
following vulnerabilities :

  - An integer overflow vulnerability exists due a failure
    to properly parse the header of a Real Media, which 
    could then trigger a heap-based buffer overflow. It is
    not yet known if this issue can be exploited to execute
    arbitrary code. (CVE-2010-3907)

  - There are two heap corruption vulnerabilities in the
    CDG decoder that arise because of a failure to validate
    indices into statically-sized arrays on the heap, which
    could allow for arbitrary code execution. (CVE-2011-0021)

  - The 'StripTags()' function in the USF and Text decoders
    may scan past the end of a subtitle in an MKV file with 
    an opening '<' char but without a corresponding closing
    '>' char, resulting in heap memory corruption. 
    (CVE-2011-0522)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0c2a0870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.videolan.org/security/sa1007.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24b9825d"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.videolan.org/security/sa1101.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.videolan.org/developers/vlc-branch/NEWS"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to VLC Media Player version 1.1.6 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/27");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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
  version =~ "^1\.1\.[0-5]($|[^0-9])"
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
      '\n  Fixed version     : 1.1.6\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));

  exit(0);
}
else exit(0, "The host is not affected since VLC "+version+" is installed.");
