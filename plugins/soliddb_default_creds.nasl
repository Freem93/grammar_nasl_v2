#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31681);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/09 21:14:09 $");

  script_name(english:"solidDB Default Credentials");
  script_summary(english:"Simulates a login using SolidConsole");

  script_set_attribute(attribute:"synopsis", value:"The remote service is protected with known credentials.");
  script_set_attribute(attribute:"description", value:
"The remote instance of solidDB uses known credentials to control
access.  With these, an attacker can gain administrative control of the
affected application.");
  script_set_attribute(attribute:"solution", value:"Change the password for each affected account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:soliddb");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("soliddb_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/soliddb", 1315, 2315);

  exit(0);
}


include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


port = get_service(svc:"soliddb", default:2315, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);


# Default accounts.
#
# nb: solidDB will block the IP temporarily after 4 unsuccessful login
#     attempts (solidDB Administration Guide, v6.0, section 3.4)
account = NULL;
naccts = 0;
# - used traditionally for evaluation databases.
account[naccts++] = make_list(
  "DBA",
  # nb: 'dba' (in hashed form)
  raw_string(0x76, 0xce, 0xa5, 0x2d, 0x72, 0x4f, 0x6f, 0x02)
);


# Check each account.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

cmd = "version";
networkname = "tcp " + get_host_name() + " " + port;
me = "nessus (" + this_host() + ")";

info = "";
output = "";
for (i=0; i<naccts; i++)
{
  # Establish a connection.
  soc = open_sock_tcp(port);
  if (!soc) break;

  # Authenticate.
  acct = account[i];
  user = acct[0];
  enc_pass = acct[1];

  req =
    raw_string(0x02, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00) +
    mkdword(1) +
    mkdword(strlen(networkname)) + networkname +
    mkdword(strlen(user)) + user +
    mkdword(strlen(enc_pass)) + enc_pass +
    mkdword(4) +
    mkdword(3) +
    mkdword(2) +
    mkdword(1) +
    mkdword(1) +
    mkdword(0) +
    mkdword(strlen(me)+3) +
    mkbyte(4) +
    mkword(strlen(me)) + me;
  send(socket:soc, data:req);
  res = recv(socket:soc, length:64, min:16);

  # If it was successful.
  if (strlen(res) == 0x23)
  {
    info += '  - ' + user + '\n';

    # Try to run a command and collect output for the report.
    if (!output && report_verbosity)
    {
      x1 = getdword(blob:res, pos:0x1b);
      x2 = getdword(blob:res, pos:0x1f);

      req2 =
        raw_string(0x02, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00) +
        mkdword(2) +
        mkdword(x1) +
        mkdword(x2) +
        mkdword(0x012d) +
        mkdword(strlen(cmd)) + cmd;
      send(socket:soc, data:req2);
      res2 = recv(socket:soc, length:1024);

      if (
        strlen(res2) > 0x17 &&
        getdword(blob:res2, pos:0x0b) == x1
      )
      {
        ofs = 0x13;
        while (len = getdword(blob:res2, pos:ofs))
        {
          if (ofs+4+len < strlen(res2))
          {
            output += substr(res2, ofs+4, ofs+4+len-1);
            ofs += len+4;
          }
          else break;
        }
      }
    }
  }
  close(soc);

  if (info && !thorough_tests) break;
}


if (info)
{
  if (report_verbosity)
  {
    report =
      '\n' +
      'Nessus was able to gain access using the following account(s) :\n' +
      '\n' +
      info;

    if (output)
    {
      output = str_replace(find:'\n', replace:'\n  ', string:output);
      output = chomp(output);

      report +=
        '\n' +
        'In addition, it successful ran the command "' + cmd + '", which produced\n' +
        'the following output :\n' +
        '\n' +
        '  ' + output + '\n';
    }
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
