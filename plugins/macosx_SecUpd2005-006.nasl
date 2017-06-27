#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(18437);
 script_version ("$Revision: 1.15 $");
 script_cvs_date("$Date: 2016/11/28 21:06:38 $");

 if (NASL_LEVEL >= 3000)
 {
   script_cve_id("CVE-2005-0524", "CVE-2005-0525", "CVE-2005-1042", "CVE-2005-1043", "CVE-2005-1333",
                "CVE-2005-1343", "CVE-2005-1720", "CVE-2005-1721", "CVE-2005-1722", "CVE-2005-1723",
                "CVE-2005-1724", "CVE-2005-1725", "CVE-2005-1726", "CVE-2005-1727", "CVE-2005-1728");
 }
 script_bugtraq_id(13491, 13899);
 script_osvdb_id(
  15183,
  15184,
  15629,
  15630,
  16074,
  16085,
  17263,
  17265,
  17266,
  17267,
  17268,
  17269,
  17270,
  17271,
  17272
 );

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2005-006)");
 script_summary(english:"Check for Security Update 2005-006");

 script_set_attribute( attribute:"synopsis",  value:
"The remote host is missing a Mac OS X update that fixes a security
issue." );
 script_set_attribute( attribute:"description",   value:
"The remote host is missing Security Update 2005-006. This security
update contains security fixes for the following application :

- AFP Server
- Bluetooth
- CoreGraphics
- Folder Permissions
- launchd
- LaunchServices
- NFS
- PHP
- VPN

These programs have multiple vulnerabilities, some of which may lead
to arbitrary code execution." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://support.apple.com/kb/TA23304"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Install Security Update 2005-006."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/03");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/06/09");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");

 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

#

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);


uname = get_kb_item("Host/uname");
# MacOS X 10.4.1
if ( egrep(pattern:"Darwin.* (7\.[0-9]\.|8\.[01]\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?2005-006", string:packages)) security_hole(0);
}
