#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
	script_id(11563);
 	script_version ("$Revision: 1.22 $");
	script_cve_id("CVE-2003-0222");
	script_bugtraq_id(7453);
	script_osvdb_id(7736);

	script_name(english:"Oracle Net Services CREATE DATABASE LINK Query Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote Oracle Database, according to its version number,
is vulnerable to a buffer overflow in the query CREATE 
DATABASE LINK. An attacker with a database account may use 
this flaw to gain the control on the whole database, or even 
to obtain a shell on this host." );
 # http://web.archive.org/web/20030915014346/http://otn.oracle.com/deploy/security/pdf/2003alert54.pdf
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6719c919" );
 script_set_attribute(attribute:"solution", value:
"Apply vendor-supplied patches." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploithub_sku", value:"EH-11-704");
 script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/04/25");
 script_set_attribute(attribute:"patch_publication_date", value: "2003/04/25");
 script_cvs_date("$Date: 2014/07/11 19:10:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
script_end_attributes();

	script_summary(english: "Checks the version of the remote Database");

	script_category(ACT_GATHER_INFO);
	script_family(english:"Databases");
	script_copyright(english:"This script is (C) 2003-2014 Tenable Network Security, Inc.");
	script_dependencie("oracle_tnslsnr_version.nasl");
        script_require_ports("Services/oracle_tnslsnr");
	exit(0);
}

include('global_settings.inc');
if ( report_paranoia < 1 ) exit(0);

port = get_kb_item("Services/oracle_tnslsnr");
if ( isnull(port)) exit(0);

version = get_kb_item(string("oracle_tnslsnr/",port,"/version"));
if (version)
{
  if(ereg(pattern:".*Version ([0-7]\.|8\.0\.[0-6]|8\.1\.[0-7]|9\.0\.[0-1]|9\.2\.0\.[0-2]).*", string:version))
	security_hole(port);
}
