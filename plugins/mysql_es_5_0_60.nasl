#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32138);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/16 14:12:51 $");

  script_cve_id("CVE-2008-2079");
  script_bugtraq_id(29106);
  script_osvdb_id(44937);
  script_xref(name:"Secunia", value:"30134");

  script_name(english:"MySQL Enterprise Server 5.0 < 5.0.60 MyISAM CREATE TABLE Privilege Check Bypass");
  script_summary(english:"Checks version of MySQL Enterprise Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server allows a local user to circumvent
privileges.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL Enterprise Server 5.0 installed on the remote
host is earlier than 5.0.60.  Such versions reportedly allow a local
user to circumvent privileges through creation of MyISAM tables using
the 'DATA DIRECTORY' and 'INDEX DIRECTORY' options to overwrite
existing table files in the application's data directory.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=32167");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.0/en/news-5-0-60.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL Enterprise Server version 5.0.60 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("mysql_func.inc");


port = get_service(svc:"mysql", default:3306, exit_on_fail:TRUE);

if (mysql_init(port:port, exit_on_fail:TRUE) == 1)
{
  variant = mysql_get_variant();
  ver = mysql_get_version();

  if (
    "Enterprise " >< variant && 
    strlen(ver) && ver =~ "^5\.0\.([0-9]|[1-5][0-9])($|[^0-9])"
  )
  {
    if (report_verbosity > 0)
    {
      report =
        '\nThe remote MySQL '+variant+'\'s version is :\n'+
        '\n  '+ver+'\n';
      security_note(port:port, extra:report);
    }
    else security_note(port);
  }
}
mysql_close();
