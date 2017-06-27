#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51091);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/19 18:10:51 $");

  script_bugtraq_id(45221);
  script_osvdb_id(69765);
  script_xref(name:"EDB-ID", value:"15706");
  script_xref(name:"Secunia", value:"42475");

  script_name(english:"Winamp < 5.601 MIDI Timestamp Stack-based Buffer Overflow");
  script_summary(english:"Checks the version number of Winamp");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a multimedia application that is
affected by stack-based buffer overflow vulnerability.");

  script_set_attribute(attribute:"description", value:
"The remote host is running Winamp, a media player for Windows.

The version of Winamp installed on the remote host is earlier than
5.601.  Such versions are potentially affected by a stack-based buffer
overflow vulnerability due to an error in the 'in_midi.ddl' plugin
that improperly serializes timestamps in MIDI files.  A malicious,
crafted MIDI file can cause the application to overwrite the saved
base pointer and allow execution of arbitrary code.");

  script_set_attribute(attribute:"see_also", value:"http://www.kryptoslogic.com/advisories/2010/kryptoslogic-winamp-midi.txt");
  script_set_attribute(attribute:"see_also", value:"http://forums.winamp.com/showthread.php?s=&threadid=159785");
  script_set_attribute(attribute:"solution", value:"Upgrade to Winamp 5.601 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/09");
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
fixed_version = '5.6.0.3091';

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
else exit(0, "The host is not affected since Winamp " + version + " is installed.");
