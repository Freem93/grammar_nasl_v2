#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38858);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2009-1831");
  script_bugtraq_id(35052);
  script_osvdb_id(54902);

  script_name(english:"Winamp < 5.552 Modern Skins Support Module (gen_ff.dll) MAKI File Handling Overflow");
  script_summary(english:"Checks the version number of Winamp");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a multimedia application that is
affected by an integer overflow vulnerability." );

  script_set_attribute(attribute:"description", value:
"The remote host is running Winamp, a media player for Windows.

The version of Winamp installed on the remote host is earlier than
5.552. Such versions are reportedly affected by an integer overflow 
vulnerability when processing '.maki' files. An attacker
could exploit this to execute arbitrary code in the context of the
affected application.");
   # http://vrt-sourcefire.blogspot.com/2009/05/winamp-maki-parsing-vulnerability.html
  script_set_attribute(attribute:"see_also", value:
"http://www.nessus.org/u?a206c855");
  script_set_attribute(attribute:"see_also", value:
"http://forums.winamp.com/showthread.php?threadid=303193#notes9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Winamp version 5.552 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-12-178");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Winamp MAKI Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(189);

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/05/22");
 script_cvs_date("$Date: 2016/11/29 20:13:38 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nullsoft:winamp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");
  exit(0);
}

# Check version of Winamp.

#
# nb : the KB item is based on GetFileVersion, which may differ
#      from what the client reports.

version = get_kb_item("SMB/Winamp/Version");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = split("5.5.5.2435", sep:'.', keep:FALSE);
for (i=0; i<max_index(fix); i++)
  fix[i] = int(fix[i]);

for (i=0; i<max_index(ver); i++)
  if ((ver[i] < fix[i]))
  {
    security_hole(get_kb_item("SMB/transport"));
    break;
  }
  else if (ver[i] > fix[i])
    break;
