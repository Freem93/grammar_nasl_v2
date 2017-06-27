#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12126);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2014/07/11 19:10:05 $");

 script_cve_id("CVE-2004-0385");
 script_bugtraq_id(9868);
 script_osvdb_id(4249, 15438);

 script_name(english:"Oracle Application Server Web Cache <= 9.0.4.0 Multiple Vulnerabilities");
 script_summary(english:"Checks for version of Oracle AS WebCache");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a heap overflow
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Oracle Application Server Web
Cache version 9.0.4.0 or older. The installed version is affected by a
heap overflow vulnerability. Provided Web Cache is running and
configured to listen on Oracle Application Server Web Cache listener
port and accept requests from any client it may be possible for an
attacker to execute arbitrary code on the remote system.");
 # http://web.archive.org/web/20040502043154/http://www.inaccessnetworks.com/ian/services/secadv01.txt
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea241a98");
 # http://web.archive.org/web/20040426054757/http://otn.oracle.com/deploy/security/pdf/2004alert66.pdf
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78a33ad1");
 script_set_attribute(attribute:"solution", value:"See the Oracle advisory referenced in the URL above.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/03/15");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/03/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/04/04");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_server_web_cache");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
 script_family(english:"Databases");

 script_dependencie("http_version.nasl", "os_fingerprint.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

banner = get_http_banner(port: port, exit_on_fail: 1);

# Oracle AS10g/9.0.4 Oracle HTTP Server OracleAS-Web-Cache-10g/9.0.4.0.0 (N)

if(egrep(pattern:"^Server:.*OracleAS-Web-Cache-10g/(9\.0\.[0-3]\.[0-9]|2\..*)", string:banner))
{
   security_hole(port);
   exit(0);
}

if(egrep(pattern:"^Server:.*OracleAS-Web-Cache-10g/9\.0\.4\.0", string:banner))
{
  os = get_kb_item("Host/OS");
  if ( !os || ("Windows" >!< os && "Tru64" >!< os && "AIX" >!< os)) security_hole ( port );
}
