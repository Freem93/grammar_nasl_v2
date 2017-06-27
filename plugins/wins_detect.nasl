#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
 script_id(54629);
 script_version("$Revision: 1.3 $");
 script_cvs_date("$Date: 2011/06/14 15:52:27 $");

 script_name(english:"WINS Server Detection");
 script_summary(english:"Tries to associate with a WINS server");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"A WINS server is running on the remote port."
 );
 script_set_attribute(
  attribute:"description", 
  value:
"The remote service is a WINS (Windows Internet Name Service) server,
which holds information about any NetBIOS-enabled hosts on the
network. 

Note that the service may allow an arbitrary user to download the
list, although some versions (eg, in Windows 2008) require an IP
address to be specifically trusted to download the list by default."
 );
 script_set_attribute(
  attribute:"solution", 
  value:
"Determine whether or not this service should be allowed by policy and
disable it if it shouldn't be."
 );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"plugin_publication_date", value: "2011/05/24");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");
 script_family(english:"Service detection");

 script_require_ports(42);
 exit(0);
}

include("global_settings.inc");
include("byte_func.inc");
include("dump.inc");
include("netop.inc");
include("wins.inc");

# Create the socket
port = 42;
if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");
s = open_sock_tcp(port);
if (!s) exit(0, "Can't open socket on port "+port+".");

# Get the information
context = wins_start_association(s:s);
if (isnull(context)) exit(1, "Failed to associate with the WINS server on port "+port+".");

# Only do the rest of the request for verbose reports
if (report_verbosity >= 2)
{
  wins_owner_records = wins_owner_records_request(s:s, context:context);
  if (!isnull(wins_owner_records) && max_index(wins_owner_records)  > 0 )
  {
  records = make_array();
  foreach owner (wins_owner_records)
  {
    address = owner['address'];
    records[address] = wins_name_records_request(s:s,
                                                  context:context,
                                                  address:address,
                                                  min_version_lo:owner['min_version_lo'],
                                                  min_version_hi:owner['min_version_hi'],
                                                  max_version_lo:owner['max_version_lo'],
                                                  max_version_hi:owner['max_version_hi']);
    if (isnull(records[address]))
      exit(1, "Failed to get information for the WINS owner '" + address + "'.");
  }

  # Put together the information and report it
  info = '\nThe following records were present on the remote WINS server :\n';
  foreach wins_host(keys(records))
  {
    info = info + '\n\tRecords stored by host ' + wins_host + '\n';
    foreach record(records[wins_host])
    {
      if (isnull(record['address']))
        info = info + '\t\t' + record['name'] + ' => ' + join(record['addresses'], sep:', ') + '\n';
      else
        info = info + '\t\t' + record['name'] + ' => ' + record['address'] + '\n';
    }
  }
  info = info + '\n';
  security_note(port:port, extra:info);
  }
  else security_note(port:port);
}
else security_note(port);

# Close the connection
wins_stop_association(s:s);
close(s);

# If we made it to the end, we know we have a valid service
register_service(port:port, proto:"wins");
