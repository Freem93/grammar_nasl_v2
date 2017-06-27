#
# (C) Tenable Network Secrity, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58604);
  script_version("$Revision: 2.12 $");
  script_cvs_date("$Date: 2015/01/27 21:15:31 $");

  script_name(english:"OS Identification : NativeLanManager");
  script_summary(english:"Checks NativeLanManager");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote operating system based on the
SMB NativeLanManager.");
  script_set_attribute(attribute:"description", value:
"The remote operating system can be identified based on its responses
to an SMB authentication request.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

os = NULL;
# nb: since the version info for Mac OS X isn't granular, keep it
#     under 70, which is the cutoff used by OS version checks, at
#     least for that OS.
confidence = 69;
type = 'general_purpose';

nativelanman = get_kb_item_or_exit('SMB/NativeLanManager');

if ('Samba 3.0.25b-apple' >< nativelanman) os = 'Mac OS X 10.5';
else if ('Samba 3.0.28a-apple' >< nativelanman) os = 'Mac OS X 10.6';
else if ('(#)PROGRAM:smbd  PROJECT:smbx-103' >< nativelanman) os = 'Mac OS X 10.7';
else if ('(#)PROGRAM:smbd  PROJECT:smbx-105' >< nativelanman) os = 'Mac OS X 10.7';
else if ('(#)PROGRAM:smbd  PROJECT:smbx-128' >< nativelanman) os = 'Mac OS X 10.8 DP1';
else if ('(#)PROGRAM:smbd  PROJECT:smbx-136' >< nativelanman) os = 'Mac OS X 10.8';
else if ('@(#)PROGRAM:smbd  PROJECT:smbx-275' >< nativelanman ) os = 'Mac OS X 10.9';
else if ('@(#)PROGRAM:smbd  PROJECT:smbx-316' >< nativelanman ) os = 'Mac OS X 10.10'; # build 14A238x (beta)

else if ('iSeries Support for Windows Network Neighborhood' >< nativelanman)
{
  os = "IBM OS/400";
  confidence = 95;
  type = "general-purpose";
}
else if ('Isilon OneFS' >< nativelanman)
{
  os = "Isilon OneFS";
  confidence = 95;
  type = "embedded";
}
else if ('GuardianOS' >< nativelanman)
{
  os = 'GuardianOS';
  match = eregmatch(string:nativelanman, pattern:"GuardianOS v\.?([0-9.]+)");
  if (!isnull(match)) {
    os = 'GuardianOS ' + match[1];
  }
  
  confidence = 95;
  type = "embedded";
}

if (!isnull(os))
{
  set_kb_item(name:'Host/OS/NativeLanManager', value:os);
  set_kb_item(name:'Host/OS/NativeLanManager/Confidence', value:confidence);
  set_kb_item(name:'Host/OS/NativeLanManager/Type', value:type);
}
