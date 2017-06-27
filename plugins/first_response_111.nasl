#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23925);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2006-6475", "CVE-2006-6476", "CVE-2006-6477");
  script_bugtraq_id(21548);
  script_osvdb_id(32347, 32348, 32349);

  script_name(english:"First Response < 1.1.1 Multiple Vulnerabilities");
  script_summary(english:"Checks version of First Response");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows application is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of First Response, an incident
response tool, that is affected by multiple vulnerabilities. 

If the First Response agent (fragent) is configured to listen for
remote SSL-enabled connections, it is reportedly possible to disable
the agent remotely by sending a series of specially crafted requests,
thereby preventing legitimate connections from a First Response
Command Console. 

Additionally, it is possible to hijack the agent by binding to the
same socket address on which it is already listening if it was bound
to the '0.0.0.0' wildcard address.  A local attacker may be able to
leverage this flaw to deny service to the agent or to conduct a
man-in-the-middle attack against connecting clients." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c4e96e5" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/454712/100/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MANDIANT First Response version 1.1.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/12/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/12/18");
 script_cvs_date("$Date: 2011/09/22 01:48:53 $");
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


# Look in the registry for the version of First Response installed.
# - version 1.1.0.
key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{B42D1E06-E04C-46DD-8EB9-469BEA526F92}/DisplayVersion";
ver = get_kb_item(key);
if (ver && ver == "1.1.0") security_hole(get_kb_item("SMB/transport"));
# - version 1.0.
key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{DB1060BF-AA42-4E11-82FA-8F31730D3710}/DisplayVersion";
ver = get_kb_item(key);
if (ver && ver == "1.0") security_hole(get_kb_item("SMB/transport"));
