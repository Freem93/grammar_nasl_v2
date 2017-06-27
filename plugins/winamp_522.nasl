#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21733);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2011/10/06 01:16:36 $");
  script_cve_id("CVE-2006-3228");
  script_bugtraq_id(18507);
  script_osvdb_id(26727);

  script_name(english:"Winamp < 5.22 Malformed Midi File Handling Buffer Overflow");
  script_summary(english:"Checks the version number of Winamp"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a multimedia application that is
prone to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Winamp, a popular media player for Windows. 

The version of Winamp installed on the remote Windows host reportedly
contains a buffer overflow in the 'in_midi.dll' library that can be
exploited using a specially crafted MIDI file to either crash the
affected application or possibly even execute arbitrary code remotely,
subject to the privileges of the user running the application." );
 script_set_attribute(attribute:"see_also", value:"http://www.fortinet.com/FortiGuardCenter/advisory/FG-2006-16.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.winamp.com/player/version-history" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Winamp version 5.22 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/06/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/25");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:nullsoft:winamp");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");
  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");
  exit(0);
}

# Check version of Winamp.

#
# nb: the KB item is based on GetFileVersion, which may differ
#     from what the client might report.

ver = get_kb_item("SMB/Winamp/Version");
if (ver && ver =~ "^([0-4]\.|5\.([01]\.|2\.[01]\.))") 
  security_hole(get_kb_item("SMB/transport"));
