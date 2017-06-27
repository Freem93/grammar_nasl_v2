#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20393);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2005-3187", "CVE-2005-3654", "CVE-2005-4085");
  script_bugtraq_id(16147, 16148, 16149);
  script_osvdb_id(22237, 22238, 22239);

  script_name(english:"WinProxy < 6.1a Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks for multiple vulnerabilities in WinProxy < 6.1a");

 script_set_attribute(attribute:"synopsis", value:
"The remote proxy is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running WinProxy, a proxy server for Windows. 

According to the Windows registry, the installed version of WinProxy
suffers from denial of service and buffer overflow vulnerabilities in
its telnet and web proxy servers.  An attacker may be able to exploit
these issues to crash the proxy or even execute arbitrary code on the
affected host." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40f07cd6" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a6c81a5" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79b3006b" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c88612f" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WinProxy version 6.1a or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Blue Coat WinProxy Host Header Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/10");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/01/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/01/05");
 script_cvs_date("$Date: 2011/09/12 01:34:03 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");
  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Look in the registry for evidence of WinProxy.
name = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/WinProxy 6/DisplayName");
if (name && name =~ "^WinProxy \(Version ([0-5]\.|6\.0)") {
  security_hole(0);
  exit(0);
}

