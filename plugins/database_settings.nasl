#
# (C) Tenable Network Security, Inc.
#

# @NOSOURCE@
# @PREFERENCES@

include("compat.inc");

if(description)
{

  script_id(33815);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/05/19 13:24:35 $");

  script_name(english:"Database settings");
  script_summary(english:"Set database preferences to perform security checks.");

  script_set_attribute(attribute:"synopsis", value:"Database settings." );
  script_set_attribute(attribute:"description", value:
"This plugin just sets global variables (SID, SERVICE_NAME, etc.), and
does not perform any security checks.");
  script_set_attribute(attribute:"solution", value:"n/a" );
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"plugin_publication_date", value: "2009/02/03");
  script_set_attribute(attribute:"plugin_type", value:"settings");
  script_end_attributes();

  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_category(ACT_SETTINGS);

  local_var preference_count;
  preference_count = 5;
  if (NASL_LEVEL < 6000)
    preference_count = 1;

  local_var i;
  local_var prefix, index_text;
  local_var legacy_compat;
  for (i = 0; i < preference_count; i++)
  {
    prefix = "";
    index_text = "";
    legacy_compat = "";
    if (i > 0)
    {
      prefix = "Additional ";
      index_text = "(" + i + ") ";
      legacy_compat = " ";
    }
    script_add_preference(name:prefix+"DB Type "+index_text+": ", type:"radio", value:"Oracle;SQL Server;MySQL;DB2;Informix/DRDA;PostgreSQL");
    script_add_preference(name:prefix+"Database service type "+index_text+": ", type:"radio", value:"SID;SERVICE_NAME");
    script_add_preference(name:prefix+"Database SID "+index_text+": ", type:"entry", value:"");
    script_add_preference(name:prefix+"Database port to use "+index_text+": ", type:"entry", value:"");
    script_add_preference(name:prefix+"Login "+index_text+": ", type:"entry", value:"");
    script_add_preference(name:prefix+"Password "+index_text+": ", type:"password", value:"");
    script_add_preference(name:prefix+"Oracle auth type"+legacy_compat+index_text+": ", type:"radio", value:"NORMAL;SYSOPER;SYSDBA");
    script_add_preference(name:prefix+"SQL Server auth type"+legacy_compat+index_text+": ", type:"radio", value:"Windows;SQL");
  }

  exit(0);
}

function store_instance_in_kb(index, service_type, service, port)
{
  local_var index_text;
  index_text = "";
  if (index > 0)
  {
    index_text = "/" + index;
  }

  # default to SID
  if (!strlen(service_type) || service_type == "SID;SERVICE_NAME")
    service_type = "SID";

  if (strlen(service))
    set_kb_item(name:"Database" + index_text + "/"+service_type, value:service);

  if (!isnull(port) && int(port) > 0)
  {
    set_kb_item(name:"Database" + index_text + "/Port", value:port);
  }
}

function store_credential_set_in_kb(index, db_type, username, password, sspi, atype)
{
  local_var index_text;
  index_text = "";
  if (index > 0)
  {
    index_text = "/" + index;
  }

  if (!isnull(db_type))
  {
    set_kb_item(name: "Database" + index_text + "/type", value: db_type);
  }

  if (strlen(username))
  {
    set_kb_item(name: "Database" + index_text + "/login", value: username);
  }

  if (strlen(password))
  {
    set_kb_item(name: "/tmp/Database" + index_text + "/password", value: password);
  }

  if (db_type == 1)
  {
    set_kb_item(name: "Database" + index_text + "/sspi", value: sspi);
  }

  if (atype)
  {
    set_kb_item(name: "Database" + index_text + "/oracle_atype", value: atype);
  }
}

function decode_db_type()
{
  local_var type;
  local_var value;
  local_var opts;
  type  = _FCT_ANON_ARGS[0];
  value = NULL;

  # Set type to default
  if ( ";" >< type )
  {
    opts = split(type,sep:";",keep:FALSE);
    type = opts[0];
  }

  if ("Oracle" >< type)
    value = 0;
  else if ("SQL Server" >< type)
    value = 1;
  else if ("MySQL" >< type)
    value = 2;
  else if ("DB2" >< type)
    value = 3;
  else if ("Informix" >< type)
    value = 4;
  else if ("PostgreSQL" >< type)
    value = 5;

  return value;
}

local_var TNS_LOGON_NORMAL, TNS_LOGON_SYSOPER, TNS_LOGON_SYSDBA;

TNS_LOGON_NORMAL    = 0;
TNS_LOGON_SYSOPER   = 64;
TNS_LOGON_SYSDBA    = 32;

local_var username, password, oracle_cred_type, mssql_cred_type, atype, sspi, port, type, service, service_type;

for (i = 0; TRUE; i++)
{
  if (i == 0)
  {
    type = script_get_preference("DB Type : ");
    db_service_type = script_get_preference("Database service type : ");
    service = script_get_preference("Database SID : ");
    port = script_get_preference("Database port to use : ");
    username = script_get_preference("Login : ");
    password = script_get_preference("Password : ");
    oracle_cred_type = script_get_preference("Oracle auth type: ");
    mssql_cred_type = script_get_preference("SQL Server auth type: ");
  }
  else
  {
    type = script_get_preference("Additional DB Type (" + i + ") : ");
    db_service_type = script_get_preference("Additional Database service type (" + i + ") : ");
    service = script_get_preference("Additional Database SID (" + i + ") : ");
    port = script_get_preference("Additional Database port to use (" + i + ") : ");
    username = script_get_preference("Additional Login (" + i + ") : ");
    password = script_get_preference("Additional Password (" + i + ") : ");
    oracle_cred_type = script_get_preference("Additional Oracle auth type (" + i + ") : ");
    mssql_cred_type = script_get_preference("Additional SQL Server auth type (" + i + ") : ");
  }

  if (!strlen(username))
    break;

  if ("Windows" >< mssql_cred_type)
  {
    sspi = TRUE;
  }
  else if ("SQL" >< mssql_cred_type)
  {
    sspi = FALSE;
  }

  if ("NORMAL" >< oracle_cred_type)
  {
    atype = TNS_LOGON_NORMAL;
  }
  else if ("SYSOPER" >< oracle_cred_type)
  {
    atype = TNS_LOGON_SYSOPER;
  }
  else if ("SYSDBA" >< oracle_cred_type)
  {
    atype = TNS_LOGON_SYSDBA;
  }

  store_instance_in_kb(
      index: i,
      service_type: db_service_type,
      service: service,
      port: port);
  store_credential_set_in_kb(
      index: i,
      db_type: decode_db_type(type),
      username: username,
      password: password,
      sspi: sspi,
      atype: atype);
}
