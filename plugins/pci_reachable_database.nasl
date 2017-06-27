#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57581);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_name(english:"PCI DSS Compliance : Database Reachable from the Internet");
  script_summary(english:"Checks a host for PCI DSS compliance");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Nessus has determined that this host is NOT COMPLIANT with PCI DSS
requirements."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a database server that is reachable from
the Internet.  This violates PCI DSS, section 1.3.7."
  );
  script_set_attribute(
    attribute:"solution",
    value:"Filter incoming traffic to this port."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.pcisecuritystandards.org/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://en.wikipedia.org/wiki/PCI_DSS"
  );

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/17");
  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Policy Compliance");
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencie("find_service2.nasl",
  "mssqlserver_detect.nasl",
  "sybase_detect.nasl",
  "mysql_unpassworded.nasl",
  "oracle_detect.nbin",
  "informix_detect.nasl",
  "db2_connection_port_detect.nasl", "db2_das_detect.nasl",
  "db2_interrupt_port_detect.nasl", "firebird_detect.nasl",
  "ingres_iigcd_detect.nasl", "ingres_iigcc_detect.nasl",
  "openbase_detect.nasl", "postgresql_detect.nasl", "soliddb_detect.nasl",
  "btrieve_detect.nasl", "derby_network_server_detect.nasl",
  "hsqldb_detect.nasl", "sapdb_detect.nasl", "soliddb_detect.nasl",
  "versant_oscssd_detect.nasl", "sqlanywhere_detect.nbin",
  "mongodb_detect.nasl", "mongodb_web_admin_detect.nasl",
  "memcached_detect.nasl");
  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('network_func.inc');

if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");



if (is_private_addr(addr: get_host_ip()) )
  on_internet = 0;
else
  on_internet = 1;

if (on_internet == 0) exit(1, "Nessus can not make a determination because the target has a private address.");


db_l = make_array( 'versant_sqlnw', 'Versant SQL Listener',
       		   'mysql', 'MySQL server',
		   'mysql_im', 'MySQL Instance Manager',
		   'versant_sqlnw', 'Versant SQL Listener',
		   'postgresql', 'PostgreSQL server',
		   'mssql', 'MS SQL server',
		   'sybase', 'Sybase / SQL server',
		   'sqlanywhere', 'Sybase SQL Anywhere',
		   'oracle_tnslsnr', 'Oracle TNS listener',
		   'informix', 'Informix server',
		   'db2c_db2', 'DB2 connection port',
		   'db2i_db2', 'DB2 interrupt port',	# ?
		   'db2das', 'DB2 Administration Server',	# ?
		   'gds_db', 'Firebird / Interbase server',
		   'iigcd', 'Ingres Data Access Server',
		   'iigcc', 'Ingres Communications Server',
		   'openbase', 'Openbase server',
		   # 'openbase_admin', 'Openbase administration server',
		   'btrieve', ' Pervasive PSQL / Btrieve server',
		   'derby', 'Derby Network Server',
		   'hsqldb_detect.nasl', 'HSQLDB server',
		   'sap_db_vserver', 'SAP DB',
		   'soliddb', 'solidDB server',
		   'versant_oscssd', 'Versant connection services daemon',
		   'mongodb', 'MongoDB Server',
                   'mongodb_rest', 'MongoDB REST Interface',
                   'memcached', 'memcached daemon'
		   );
l = '';
foreach svc (keys(db_l))
{
  if (svc == 'mongodb_rest')
    ports = get_kb_list('mongodb_rest');
  else
    ports = get_kb_list('Services/'+svc);

  if (! isnull(ports))
  {
    foreach p (ports)
    {
      if (get_kb_item(svc+'/blocked/'+p)) continue;
      security_hole(port: p, extra: strcat("
A ",  db_l[svc], " is listening on this port.
Databases should not be reachable from Internet, according to PCI DSS.
"));
    }
  }
}
