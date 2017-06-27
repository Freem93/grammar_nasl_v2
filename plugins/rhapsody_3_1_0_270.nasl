#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21141);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2006-0323");
  script_bugtraq_id(17202);
  script_xref(name:"OSVDB", value:"24061");

  script_name(english:"Rhapsody SWF File Handling Buffer Overflow");
  script_summary(english:"Checks version of Rhapsody");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows application is affected by a buffer overflow flaw." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the installed version of Rhapsody on
the remote host suffers from a buffer overflow involving SWF files. 
To exploit this issue, a remote attacker needs to convince a user to
attempt to play a maliciously crafted SWF file using the affected
application." );
 script_set_attribute(attribute:"see_also", value:"http://service.real.com/realplayer/security/03162006_player/en/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Rhapsody 3 build 1.0.270 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/22");
 script_cvs_date("$Date: 2011/10/06 01:39:40 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencie("rhapsody_detect.nasl");
  script_require_keys("SMB/Rhapsody/Version");

  exit(0);
}


# Check version of Rhapsody.
ver = get_kb_item("SMB/Rhapsody/Version");
if (!ver) exit(0);

# There's a problem if it's version [3.0.0.815, 3.1.0.270).
iver = split(ver, sep:'.', keep:FALSE);
if (
  int(iver[0]) == 3 &&
  (
    (int(iver[1]) == 0 && int(iver[2]) == 0 && int(iver[3]) >= 815) ||
    (int(iver[1]) == 1 && int(iver[2]) == 0 && int(iver[3]) < 270)
  )
) security_hole(get_kb_item("SMB/transport"));
