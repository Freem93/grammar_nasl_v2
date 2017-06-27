#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(50379);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/06/20 17:20:09 $");

  script_cve_id("CVE-2010-1523", "CVE-2010-3137", "CVE-2010-4371");
  script_bugtraq_id(42747, 44094, 44466);
  script_osvdb_id(67532, 68644, 68645, 69206);
  script_xref(name:"EDB-ID", value:"14789");
  script_xref(name:"Secunia", value:"41093");
  script_xref(name:"Secunia", value:"41824");

  script_name(english:"Winamp < 5.59 build 3033 Multiple Vulnerabilities");
  script_summary(english:"Checks the version number of Winamp");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a multimedia application that is
affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote host is running Winamp, a media player for Windows.

The version of Winamp installed on the remote host is earlier than
5.59 build 3033.  Such versions are potentially affected by multiple
vulnerabilities :

  - Winamp loads libraries in an insecure manner. 
    (CVE-2010-3137)

  - An integer overflow vulnerability exists in the 
    'in_mkv.dll' plugin when parsing MKV content.

  - A heap-based buffer overflow vulnerability exists in
    the 'in_midi.dll' plugin when parsing MIDI content.

  - A stack-based buffer overflow vulnerability exists in
    the 'in_mod.dll' plugin when parsing Multitracker 
    Module files.

  - A heap-based buffer overflow vulnerability exists in
    the 'in_nsv.dll' plugin when parsing NSV content.

  - A heap-based buffer overflow vulnerability exists
    when parsing VP6 video content.");

  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2010-95/");
  script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/winamp_1-adv.txt");
  script_set_attribute(attribute:"see_also", value:"http://forums.winamp.com/showthread.php?t=322995");
  script_set_attribute(attribute:"solution", value:"Upgrade to Winamp 5.59 build 3033 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/31"); #CVE-2010-3137
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/28");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nullsoft:winamp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Winamp/Version");
fixed_version = '5.5.9.3033';

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item("SMB/Winamp/Path");
    if (isnull(path)) path = 'n/a';

    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, 'The host is not affected because winamp.exe version ' + version + ' was found.');
