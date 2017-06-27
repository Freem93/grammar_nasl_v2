#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(16204);
  script_version("$Revision: 1.12 $");
  script_cve_id("CVE-2004-0820");
  script_bugtraq_id(11053);
  script_osvdb_id(9195);

  script_name(english:"Winamp < 5.0.5 Skin File (.WSZ) Local Zone Arbitrary Code Execution");

  script_set_attribute(
    attribute:'synopsis',
    value:'The version of Winamp on the remote host is vulnerable to a buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote host is using Winamp, a popular media player
which handles many files format (mp3, wavs and more...)

The remote version of this software is vulnerable to a code execution
flaw when processing a malformed .WSZ Winamp Skin file.

An attacker may exploit this flaw by sending a malformed .wsz file
to a victim on the remote host, and wait for him to load it within
Winamp."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to Winamp 5.0.5 or newer"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.securityfocus.com/archive/1/373146'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/25");
 script_cvs_date("$Date: 2016/11/29 20:13:38 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nullsoft:winamp");
  script_end_attributes();

  script_summary(english:"Determines the version of Winamp");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"Windows");
  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");
  exit(0);
}

#

version = get_kb_item("SMB/Winamp/Version");
if ( ! version ) exit(0);

if(version =~ "^([0-4]\.|5\.0\.[0-4]\.)")
  security_hole(get_kb_item("SMB/transport"));
