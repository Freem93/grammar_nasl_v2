#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25759);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/11/28 21:52:57 $");

  script_cve_id("CVE-2007-3780", "CVE-2007-3781", "CVE-2007-3782");
  script_bugtraq_id(25017);
  script_osvdb_id(36732, 37782, 37783);

  script_name(english:"MySQL Community Server 5.0 < 5.0.45 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MySQL Community Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is susceptible to multiple attacks.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL Community Server installed on the remote host
is reportedly affected by a denial of service vulnerability that can
lead to a server crash with a specially crafted password packet. 

It is also affected by a privilege escalation vulnerability because
'CREATE TABLE LIKE' does not require any privileges on the source
table, which allows an attacker to create arbitrary tables using the
affected application.");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.0/en/news-5-0-45.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL Community Server version 5.0.45 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 264);

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("mysql_func.inc");


# nb: banner checks of open source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2)
  exit(1, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

port = get_service(svc:"mysql", default:3306, exit_on_fail:TRUE);

if (mysql_init(port:port, exit_on_fail:TRUE) == 1)
{
  variant = mysql_get_variant();
  ver = mysql_get_version();

  if ("Community" >< variant && ver =~ "^5\.0\.([0-9]|[1-3][0-9]|4[0-4])($|[^0-9])")
  {
    report = '\nThe remote MySQL Community Server\'s version is :\n\n  '+ver+'\n';
    security_warning(port:port, extra:report);
  }
}
mysql_close();
