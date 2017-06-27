#TRUSTED 91b8ac7e163b2588d6510630752f355db024db2f297f308582f3f6127a4317104f53db2e48d4604da131e6f9a1e8573c3f6972c608cf186f2dd2ceea0e3fd9e947a15cf6457869994377014ee65047c152ca4135af1454e0d9ef1144bc6912d5f83cc362a081aa5f008fc2759299fbf6b86982fb3ed785fa77671128550acf1da0c5d2dad149ec972eeedf6ab8a88bb44c988a4ee8270e9eb007e7797a072ab836cdc15d07f3338ccae814da092b681e44073da2497eb50f733beba1f5c02fbd4f9ce05da26c5145fba4347da3909dbb95bee84577868afd1872e20c1ce11e1e11394b49339ce755c616fb3198e1b79ef1a7feacb39137c71d7c8d549cf4cee9d6658361064152a8b543f8e2c138381a27679ba1592615f2b84e74eb57cc345cbb9b1905ef4a37da54ae5f191c4eb4944f3fac2739d46749379557735fbed88c01032befc9c2f746cb00fc879961020a0e1e8e2335afe6915cdf184ea64c65756db17fe664b56fe8cd41af725c5ee5b390c6c33834c6c7da78c79590fed19df7ada236a034c6a0ebd41db284c6d5d480036ffd310186156f9e7c9a15fb0559cbb80895ffe4a31b17c276c25b2c0edc6981bc40c9a9e81f940bb0b6b3ea84b11d9aa0cd425b916b0c11c4059e69dbb75034cd9626435ae01abdbabf99ef461d4cd189954b7ab0b9e8c5e2f0d106ac9866af7330128deba497c4f0995a1fb1d5ac
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69482);
  script_version("1.3");

  script_name(english:"Microsoft SQL Server STARTTLS Support");
  script_summary(english:"Checks if service supports STARTTLS");

  script_set_attribute(attribute:"synopsis", value:
"The remote service supports encrypting traffic.");
  script_set_attribute(attribute:"description", value:
"The remote Microsoft SQL Server service supports the use of
encryption initiated during pre-login to switch from a cleartext to an
encrypted communications channel.");

  script_set_attribute(attribute:"see_also", value:"http://msdn.microsoft.com/en-us/library/dd304523.aspx");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/04");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/06/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("mssqlserver_detect.nasl");
  script_require_ports("Services/mssql", 1433);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("x509_func.inc");

app = "Microsoft SQL Server";

# Get the ports that MSSQL has been found on.
port = get_service(svc:"mssql", default:1433, exit_on_fail:TRUE);

# Find out if the port is open.
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

# Connect to the port.
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SVC_FAIL, app, port);

# All parameters in TDS are big-endian.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# Send the STARTTLS command.
soc = mssql_starttls(socket:soc);
if (!soc) exit(1, "The " + app + " instance on port " + port + " didn't accept our STARTTLS command.");
set_kb_item(name:"mssql/" + port + "/starttls", value:TRUE);

# Call get_server_cert() regardless of report_verbosity so the cert
# will be saved in the KB.
cert = get_server_cert(
  port     : port,
  socket   : soc,
  encoding : "der",
  encaps   : ENCAPS_TLSv1
);

# Clean up.
close(soc);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  info = "";

  cert = parse_der_cert(cert:cert);
  if (!isnull(cert))
    info = dump_certificate(cert:cert);

  if (info)
  {
    snip = crap(data:"-", length:30) + " snip " + crap(data:"-", length:30);

    report = string(
      "\nHere is the " + app + "'s SSL certificate that Nessus",
      "\nwas able to collect after sending a pre-login packet :",
      "\n",
      "\n", snip,
      "\n", info,
      "\n", snip,
      "\n"
    );
  }
  else
  {
    report = string(
      "\nThe remote service responded to the pre-login packet in a way that",
      "\nsuggests that it supports encryption. However, Nessus failed to",
      "\nnegotiate a TLS connection or get the associated SSL certificate,",
      "\nperhaps because of a network connectivity problem or the service",
      "\nrequires a peer certificate as part of the negotiation.",
      "\n"
    );
  }
}

security_note(port:port, extra:report);
