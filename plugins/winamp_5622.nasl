#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56681);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/06 17:22:03 $");

  script_bugtraq_id(50387);
  script_osvdb_id(76634, 76635, 76636);

  script_name(english:"Winamp < 5.622 Multiple Vulnerabilities");
  script_summary(english:"Checks the version number of Winamp");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a multimedia application that is
affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote host is running Winamp, a media player for Windows. 

The version of Winamp installed on the remote host is earlier than
5.622 and is affected by the following overflow vulnerabilities :

  - A heap-based buffer overflow exists in the plugin 
    'in_midi.dll' when processing the 'iOffsetMusic' value
    in the 'Creative Music Format' (CMF) header.

  - A heap-based buffer overflow exists in the plugin 
    'in_mod.dll' when processing the 'channels' value in 
    the 'Advanced Module Format' (AMF) header.

  - A heap-based buffer overflow exists in the plugin 
    'in_nsv.dll' when processing the 'toc_alloc' value in 
    the 'Nullsoft Streaming Video' (NSF) header.

  - Integer overflow errors exist in the 'TSCC', 'RGB', and
    'YUV' decoders.");

  script_set_attribute(attribute:"see_also", value:"http://forums.winamp.com/showthread.php?t=332010");
  script_set_attribute(attribute:"solution", value:"Upgrade to Winamp 5.622 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/31");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nullsoft:winamp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Winamp/Version");
fixed_version = '5.6.2.3189';

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
else exit(0, "The Winamp " + version + " install on the host is not affected.");
