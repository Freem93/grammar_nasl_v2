#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25198);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/05/20 14:21:42 $");

  script_cve_id("CVE-2007-2583", "CVE-2007-2692");
  script_bugtraq_id(23911);
  script_osvdb_id(34734, 34765);
  script_xref(name:"EDB-ID", value:"30020");

  script_name(english:"MySQL Crafted IF Clause Divide-by-zero NULL Dereference DoS");
  script_summary(english:"Checks version of MySQL");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is prone to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host reportedly is
affected by a denial of service vulnerability that may be triggered
with a specially crafted IF query.  An attacker who can execute
arbitrary SELECT statements may be able to leverage this issue to
crash the affected service.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=27513");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.0/en/news-5-0-41.html");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-18.html");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.0/en/news-5-0-40.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL Community Server 5.0.41 / 5.1.18 / Enterprise Server
5.0.40 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/29");

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

  if (
    (
      "Enterprise" >< variant && 
      ver =~ "^5\.0\.([0-9]|[1-3][0-9])($|[^0-9])"
    ) ||
    ver =~ "^5\.(0\.([0-9]|[1-3][0-9])|1\.([0-9]|1[1-7]))($|[^0-9])"
  )
  {
    report =
      '\nThe remote MySQL '+mysql_get_variant()+'\'s version is :\n'+
      '\n  '+ver+'\n';
    security_warning(port:port, extra:report);
  }
}
mysql_close();
