#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(26918);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2016/12/09 20:54:58 $");
 script_bugtraq_id(990, 11199);
 script_osvdb_id(297, 3106, 10050);
 script_cve_id("CVE-1999-0504", "CVE-1999-0505", "CVE-1999-0506", "CVE-2000-0222","CVE-2005-3595");

 script_name(english:"Microsoft Windows SMB Blank Administrator Password");
 script_summary(english:"Attempts to log into the remote host");

 script_set_attribute(attribute:"synopsis", value:"It is possible to log into the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is running one of the Microsoft Windows operating
systems. It was possible to log into it using the administrator
account with a blank password.");
  script_set_attribute(attribute:"solution", value:"Set a password to the administrator account");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows Authenticated Powershell Command Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/02/15");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/04");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_login.nasl");
 script_require_keys("SMB/blank_admin_password");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");

val = get_kb_item("SMB/blank_admin_password");

if (val)
  security_hole(kb_smb_transport());

