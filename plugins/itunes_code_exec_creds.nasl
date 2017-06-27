#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20219);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/08/03 13:57:41 $");

  script_cve_id("CVE-2005-2938");
  script_bugtraq_id(15446);
  script_osvdb_id(20988);

  script_name(english:"Apple iTunes For Windows iTunesHelper.exe Path Subversion Local Privilege Escalation (credentialed check)");
  script_summary(english:"Checks for an local code execution vulnerability in iTunes for Windows");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a local
code execution flaw.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes for Windows on the remote host launches a
helper application by searching for it through various system paths.
An attacker with local access can leverage this issue to place a
malicious program in a system path and have it called before the
helper application.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d16d359");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2005/Nov/msg00001.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes 6 for Windows or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/16");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Look in the registry for iTunes.
ver = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{872653C6-5DDC-488B-B7C2-CF9E4D9335E5}\DisplayVersion");
if (ver && ver =~ "^[0-5]\.") security_hole(get_kb_item("SMB/transport"));
