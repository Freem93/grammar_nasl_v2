#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33820);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2008-3567");
  script_bugtraq_id(30539);
  script_osvdb_id(47347);
  script_xref(name:"Secunia", value:"31371");

  script_name(english:"Winamp < 5.541 NowPlaying Feature Metadata XSS");
  script_summary(english:"Checks the version number of Winamp"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a multimedia application that is
affected by a cross-site script vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Winamp, a media player for Windows. 

The version of Winamp installed on the remote host is earlier than
5.541. Such versions reportedly contain a cross-site scripting vulnerability
involving the software's 'NowPlaying' feature because the embedded 
browser fails to sanitize metadata in media files of JavaScript before
displaying it to the user." );
 script_set_attribute(attribute:"see_also", value:"http://blog.watchfire.com/wfblog/2008/09/winamp-nowplayi.html" );
 script_set_attribute(attribute:"see_also", value:"http://forums.winamp.com/showthread.php?threadid=295505" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Winamp version 5.541 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/05");
 script_cvs_date("$Date: 2016/05/06 17:22:03 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:nullsoft:winamp");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");
  exit(0);
}

# Check version of Winamp.

#
# nb: the KB item is based on GetFileVersion, which may differ
#     from what the client reports.

version = get_kb_item("SMB/Winamp/Version");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = split("5.5.4.2165", sep:'.', keep:FALSE);
for (i=0; i<max_index(fix); i++)
  fix[i] = int(fix[i]);

for (i=0; i<max_index(ver); i++)
  if ((ver[i] < fix[i]))
  {
    security_warning(get_kb_item("SMB/transport"));
    break;
  }
  else if (ver[i] > fix[i])
    break;
