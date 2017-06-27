#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(47717);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2011/04/13 18:00:08 $");

  script_bugtraq_id(41591);
  script_osvdb_id(66276);

  script_name(english:"Winamp < 5.58 Buffer Overflow");
  script_summary(english:"Checks the version number of Winamp");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a multimedia application that is
affected by a stack-based buffer overflow vulnerability." );

  script_set_attribute(attribute:"description", value:
"The remote host is running Winamp, a media player for Windows.

The version of Winamp installed on the remote host is earlier than
5.58. Such versions are reportedly affected by a stack-based buffer
overflow vulnerability when parsing VP6 video content.   An attacker,
exploiting this flaw, can execute arbitrary code in the context of the
affected application.");

  script_set_attribute(attribute:"see_also", value:
"http://www.winamp.com/help/Version_History#Winamp_5.58");
  script_set_attribute(attribute:"see_also", value:
"http://forums.winamp.com/showthread.php?t=320278");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Winamp version 5.58 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/14");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nullsoft:winamp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");
  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

# Check version of Winamp.

#
# nb : the KB item is based on GetFileVersion, which may differ
#      from what the client reports.

version = get_kb_item_or_exit("SMB/Winamp/Version");

if (ver_compare(ver:version, fix:'5.5.8.2975') == -1)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item("SMB/Winamp/Path");
    report = 
      '\nPath    : ' + path + 
      '\nVersion : ' + version + 
      '\nFix     : 5.5.8.2975';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else
    security_hole(port:get_kb_item("SMB/transport"));

  exit(0);
}
else exit(0, 'The host is not affected because winamp.exe version '+version+' was found.');
