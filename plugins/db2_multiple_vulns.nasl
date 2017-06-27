#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 2191 ) exit(0);

include("compat.inc");

if (description)
{
 script_id(15486);
 script_version("$Revision: 1.31 $");
 script_cvs_date("$Date: 2016/12/06 20:03:50 $");

 script_cve_id("CVE-2004-1372","CVE-2005-0417","CVE-2005-4863","CVE-2005-4864","CVE-2005-4865","CVE-2005-4866","CVE-2005-4867",
   "CVE-2005-4868","CVE-2005-4869","CVE-2005-4870","CVE-2005-4871");
 script_bugtraq_id(11405, 11404, 11403, 11402, 11401, 11400, 11399, 11398, 
   11397, 11396, 11390, 12170, 11327, 11089, 12508, 12509, 12510, 12511, 
   12512, 12514);
 script_osvdb_id(
  9525,
  9526,
  10514,
  10515,
  10517,
  10518,
  10523,
  12754,
  12755,
  12756,
  12757,
  12758,
  12759,
  14661
 );
 script_xref(name:"Secunia", value:"12436");
 script_xref(name:"Secunia", value:"12733");
 script_xref(name:"Secunia", value:"12733");

 script_name(english:"IBM DB2 < 8 Fix Pack 7a Multiple Vulnerabilities");
 script_summary(english:"IBM DB2 version check.");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote database server is affected by multiple vulnerabilities."
 );
 script_set_attribute( attribute:"description",  value:
"The remote host is running a vulnerable version of IBM DB2.

There are multiple remote buffer overflow vulnerabilities in this
version that could allow an attacker to cause a denial of service, or
possibly execute arbitrary code." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.ngssoftware.com/advisories/db223122004K.txt"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/vulnwatch/2004/q3/36"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2004/Dec/353"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2005/Jan/28"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2005/Jan/31"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2005/Jan/32"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2005/Jan/33"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2005/Jan/34"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2005/Jan/35"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2005/Jan/37"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2005/Jan/38"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to IBM DB2 V8 Fix Pack 7a or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_cwe_id(119, 200, 264);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/01");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_family(english:"Databases");
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

 script_dependencies("db2_das_detect.nasl");
 script_require_ports("Services/db2das", 523);
 exit(0);
}

#

port = get_kb_item("Services/db2das");
if (!port) port = 523;
if (! get_port_state(port) ) exit(0, "TCP port "+port+" is closed.");

soc = open_sock_tcp(port);
if ( ! soc ) exit(1, "Cannot connect to TCP port "+port+".");
r = recv(socket:soc, length:4096);
close(soc);
if ( ! r ) exit(1, "No answer from port "+port+".");

sql = strstr(r, "SQL0");
if ( ! sql ) exit(1, "Unexpected answer from port "+port+".");

if ( ereg(pattern:"^SQL0([0-7][0-9]{3}|80[01][0-9])", string:sql) ) security_hole(port);
