#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19217);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-2310");
  script_bugtraq_id(14276);
  script_osvdb_id(17897);

  script_name(english:"Winamp < 5.093 Malformed ID3v2 Tag Handling Buffer Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"A multimedia application that is affected by a buffer overflow
vulnerability is installed on the remote Windows host." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Winamp, a popular media player for Windows. 

The installed version of Winamp suffers from a buffer overflow
vulnerability when processing overly-long ID3v2 tags in an MP3 file. 
An attacker may be able to exploit this flaw to execute arbitrary code
on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/405280/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Winamp version 5.093 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/07/14");
 script_cvs_date("$Date: 2011/04/13 18:00:08 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:nullsoft:winamp");
script_end_attributes();

  script_summary(english:"Checks for malformed ID3v2 tag buffer overflow vulnerability in Winamp");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");
  exit(0);
}

#

ver = get_kb_item("SMB/Winamp/Version");
if (
  ver && 
  # nb: versions < 5.093 are possibly affected.
  ver =~ "^([0-4]\.|5\.0\.([0-8]\.|9\.[0-2]))"
) {
  security_hole(get_kb_item("SMB/transport"));
}
