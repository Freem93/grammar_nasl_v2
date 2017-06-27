#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(24905);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2014/05/26 01:15:51 $");

 script_cve_id("CVE-2007-1420");
 script_bugtraq_id(22900);
 script_osvdb_id(33974);

 script_name(english:"MySQL Single Row Subselect Remote DoS");
 script_summary(english:"Checks the remote MySQL version");

 script_set_attribute(attribute:"synopsis", value:"The remote database server is prone to a denial of service attack.");
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of MySQL on the remote host is
older than 5.0.37. Such versions are vulnerable to a remote denial of
service when processing certain single row subselect queries. A
malicious user can crash the service via a specially crafted SQL
query.");
 script_set_attribute(attribute:"see_also", value:"http://www.sec-consult.com/284.html");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/462339/100/0/threaded");
 script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.0/en/news-5-0-37.html");
 script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 5.0.37 or newer.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/30");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
 script_family(english:"Databases");

 script_dependencie("mysql_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/mysql", 3306);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Only run the plugin if we're being paranoid to avoid false-positives,
# which might arise because the software is open source.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("Services/mysql");
if (!port) port = 3306;
if (!get_tcp_port_state(port)) exit(0);


ver = get_mysql_version(port:port);
if(ver==NULL) exit(0);
if(ereg(pattern:"^5\.0\.([0-9]($|[^0-9])|[12][0-9]($|[^0-9])|3[0-6]($|[^0-9]))", string:ver))
  security_note(port);
