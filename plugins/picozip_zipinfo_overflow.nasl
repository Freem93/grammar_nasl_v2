#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21697);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2006-2909");
  script_bugtraq_id(18425);
  script_osvdb_id(26447);

  script_name(english:"PicoZip ZipInfo.dll Filename Handling Buffer Overflow");
  script_summary(english:"Checks version of PicoZip");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
buffer overflow." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PicoZip, a file compression utility for
Windows. 

According to the registry, the version of PicoZip installed on the
remote Windows host fails to properly check the size of filenames
before copying them into a finite-sized buffer within the
'zipinfo.dll' info tip shell extension.  Using a specially crafted
ACE, RAR, or ZIP file, an attacker may be able to exploit this issue
to execute arbitrary code on the affected host subject to the
privileges of the user running the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2006-42/advisory/" );
 script_set_attribute(attribute:"see_also", value:"http://www.picozip.com/changelog.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PicoZip version 4.02 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/06/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/06/14");
 script_cvs_date("$Date: 2011/10/06 00:55:10 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Look in the registry for evidence of PicoZip.
name = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/Acubix PicoZip_is1/DisplayName");
if (name && name =~ "PicoZip ([0-3]\.|4\.0($|[01]([^0-9]|$)))")
  security_hole(get_kb_item("SMB/transport"));
