#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11870);
 script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2016/08/01 15:55:04 $");

 script_cve_id("CVE-2000-0199");
 script_bugtraq_id(1055);
 script_osvdb_id(10155);

 script_name(english:"Microsoft SQL Server < 7 Local Privilege Escalation");
 script_summary(english:"Microsoft SQL less than or equal to 7 may be misconfigured");

 script_set_attribute(attribute:"synopsis", value:
"The remote SQL Server is affected by a local privilege escalation
vulnerability.");
 script_set_attribute(attribute:"description", value:
"Based on its version number, the remote host may be vulnerable to a
local exploit wherein an authenticated user can obtain and crack SQL
usernames and passwords from the registry. 

An attacker may use this flaw to elevate their privileges on the local
database. 

*** This alert might be a false positive, as Nessus did not actually
*** check for this flaw but relied solely on the presence of Microsoft
*** SQL 7 to issue this alert.");
 script_set_attribute(attribute:"see_also", value:"http://www.iss.net/threats/advise45.html");
 script_set_attribute(attribute:"solution", value:
"Ensure that the configuration has enabled Always prompting for login
name and password.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/10/08");
 script_set_attribute(attribute:"vuln_publication_date", value:"2000/03/14");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Databases");

 script_dependencie("mssql_version.nasl");
 script_require_ports(139,445);
 script_require_keys("mssql/installed");
 exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");

sql_ver_list = get_kb_list("mssql/installs/*/SQLVersion");
if (isnull(sql_ver_list)) audit(AUDIT_NOT_INST, "Microsoft SQL Server");

port = kb_smb_transport();

foreach item (keys(sql_ver_list))
{
  version = get_kb_item(item);
  if (!isnull(version) && egrep(pattern:"^[67]\..*" , string:version))
  {
    security_hole(port);
    exit(0);
  }
}

audit(AUDIT_INST_VER_NOT_VULN, "Microsoft SQL Server");
