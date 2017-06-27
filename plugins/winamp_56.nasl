#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(50846);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/06/20 17:20:09 $");

  script_cve_id(
    "CVE-2010-2586",
    "CVE-2010-4370",
    "CVE-2010-4371",
    "CVE-2010-4372",
    "CVE-2010-4373",
    "CVE-2010-4374"
  );
  script_bugtraq_id(45097);
  script_osvdb_id(68644, 68645, 69534, 69535, 69597, 69598);
  script_xref(name:"Secunia", value:"42004");

  script_name(english:"Winamp < 5.6 Multiple Vulnerabilities");
  script_summary(english:"Checks the version number of Winamp");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a multimedia application that is
affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote host is running Winamp, a media player for Windows. 

The version of Winamp installed on the remote host is earlier than
5.6.  Such versions are potentially affected by the following
vulnerabilities :

  - An integer overflow vulnerability exists in the 
    'in_nsv.dll' plugin when parsing the table of contents
    of a NullSoft Video (NSV) stream or file. 
    (CVE-2010-2586)

  - A heap-based buffer overflow vulnerability exists in
    the 'in_midi.dll' plugin when parsing MIDI content.
    (CVE-2010-4370)

  - A buffer overflow vulnerability exists in the 'in_mod'
    plugin and is related to the comment box.
    (CVE-2010-4371)

  - Another integer overflow vulnerability exists in the 
    'in_nsv' plugin due to improper memory allocation for
    Nullsoft Video (NSV) metadata. 
    (CVE-2010-4372)

  - An error exists in the 'in_mp4' plugin which allows
    remote attackers to use either crafted metadata or 
    album art in an MP4 file to cause a denial of service.
    (CVE-2010-4373)

  - An error exists in the 'in_mkv' plugin which allows
    remote attackers to use a crafted Matroska Video (MKV)
    file to cause a denial of service. 
    (CVE-2010-4374)"
  );

  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2010-127/");
  script_set_attribute(attribute:"see_also", value:"http://forums.winamp.com/showthread.php?threadid=159785");
  script_set_attribute(attribute:"see_also", value:"http://forums.winamp.com/showthread.php?t=324322");
  script_set_attribute(attribute:"solution", value:"Upgrade to Winamp 5.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/30");
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
fixed_version = '5.6';

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
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
else exit(0, "The remote host is not affected since Winamp " + version + " is installed.");
