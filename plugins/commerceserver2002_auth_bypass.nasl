#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(21205);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2006-1257");
  script_bugtraq_id(17134);
  script_osvdb_id(24121);

  script_name(english:"Microsoft Commerce Server 2002 authfiles/login.asp Authentication Bypass");
  script_summary(english:"Checks version of Microsoft Commerce Server 2002");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web application may be vulnerable to an authentication
bypass attack." );
 script_set_attribute(attribute:"description", value:
"The version of Microsoft Commerce Server 2002 installed on the remote
host may enable an attacker to bypass authentication if the sample
files from the 'AuthFiles' folder are installed under the web server's
document root. 

Note that successful exploitation of this issue requires knowledge of
the location of the sample files as well as a valid user name." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/427974/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f31fa25" );
 script_set_attribute(attribute:"solution", value:
"Apply Commerce Server 2002 Service Pack 2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/04/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/17");
 script_cvs_date("$Date: 2011/03/16 14:54:11 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1);


# Get Commerce Server's version number from the registry.
subkey = "{E39DA45E-B9E6-412D-BEDE-EFD7BC1DACA6}";
key = string("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/", subkey, "/DisplayVersion");
ver = get_kb_item(key);
if (isnull(ver)) exit(0);


# There's a problem if the version is < 4.5.3320.00.
iver = split(ver, sep:'.', keep:FALSE);
if (
  int(iver[0]) < 4 ||
  (
    int(iver[0]) == 4 &&
    (
      int(iver[1]) < 5 ||
      (int(iver[1]) == 5 && int(iver[2]) < 3320)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
