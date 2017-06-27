#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34160);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/16 14:12:51 $");

  script_cve_id("CVE-2008-3963");
  script_bugtraq_id(31081);
  script_osvdb_id(48021);

  script_name(english:"MySQL 5.1 < 5.1.26 Empty Bit-String Literal Token SQL Statement DoS");
  script_summary(english:"Checks version of MySQL 5.1 Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is susceptible to a denial of service
attack.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL 5.1 installed on the remote host is earlier than
5.1.26.  A bug in such versions can lead to a server crash in
'Item_bin_string::Item_bin_string' when handling an empty bit-string
literal (b'').  Using a simple SELECT statement, an authenticated
remote user can leverage this issue to crash the database server and
deny service to legitimate users.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=35658");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-26.html");
  script_set_attribute(attribute:"see_also", value:"http://www.openwall.com/lists/oss-security/2008/09/09/4");
  script_set_attribute(attribute:"see_also", value:"http://www.openwall.com/lists/oss-security/2008/09/09/7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.1.26.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(134);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

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
  version = mysql_get_version();

  if (
    strlen(version) &&
    version =~ "^5\.1\.([0-9]|1[0-9]|2[0-5])($|[^0-9])"
  )
  {
    if (report_verbosity > 0)
    {
      report = '\nThe remote MySQL server\'s version is :\n\n  '+version+'\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
mysql_close();
