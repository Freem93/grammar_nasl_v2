#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14343);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2013/08/14 20:44:38 $");

 script_cve_id("CVE-2004-0457");
 script_bugtraq_id(10969);
 script_osvdb_id(9015);
 script_xref(name:"DSA", value:"540");
 
 script_name(english:"MySQL < 4.0.21 mysqlhotcopy Insecure Temporary File Creation");
 script_summary(english:"Checks for the remote MySQL version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by an insecure temporary file
creation vulnerability.");
 script_set_attribute(attribute:"description", value:
"You are running a version of MySQL which is older than version 4.0.21.

Mysqlhotcopy is reported to contain an insecure temporary file 
creation vulnerability. The result of this is that temporary files 
created by the application may use predictable filenames. 

A local attacker could potentially exploit this vulnerability to 
execute symbolic link file overwrite attacks. 

*** Note : this vulnerability is local only");
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of MySQL 4.0.21 or newer.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/23");
 script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/19");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
 script_family(english:"Databases");

 script_dependencie("mysql_version.nasl");
 script_require_ports("Services/mysql", 3306);
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");

port = get_kb_item("Services/mysql");
if(!port)port = 3306;

ver=get_mysql_version(port:port);
if ((isnull)) exit(0);
if(ereg(pattern:"^3\.|4\.0\.([0-9]|1[0-9]|20)[^0-9]", string:ver))security_warning(port);	  

