#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57272);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/01/05 18:44:51 $");

  script_bugtraq_id(50881);
  script_osvdb_id(77429);

  script_name(english:"FTPS Cleartext Fallback Security Bypass");
  script_summary(english:"Detects an FTPS server that doesn't close failed SSL connections.");

  script_set_attribute(attribute:"synopsis", value:
"The FTPS server on the remote host falls back to cleartext
communication if SSL negotiations fail.");
  script_set_attribute(attribute:"description", value:
"The remote FTPS server running on the remote host is affected by a
security bypass vulnerability due to accepting unencrypted commands if
SSL negotiations fail. A man-in-the-middle attacker can exploit this
to intercept credentials and modify files.");
  script_set_attribute(attribute:"see_also", value:"http://www.serv-u.com/releasenotes/");
  script_set_attribute(attribute:"solution", value:
"If using Serv-U, upgrade to version 11.1.0.3 or later. Otherwise,
contact the vendor for a patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:serv-u:serv-u");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 990);

  exit(0);
}

include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

# Get all known FTP ports, forking as necessary.
port = get_ftp_port(default:990);

# Ignore the port if it's not known to be an SSL port, since trying
# this against an unencrypted port would result in a false positive.
encaps = get_kb_item_or_exit("Transports/TCP/" + port);
if (encaps < ENCAPS_SSLv2 || encaps > COMPAT_ENCAPS_TLSv12)
  exit(0, "The FTP server on port " + port + " does not appear to be FTPS.");

# Open a connection to the FTPS port, forcing it to not negotiate an
# SSL session.
soc = open_sock_tcp(port, transport:ENCAPS_IP);
if (!soc) exit(1, "TCP connection failed to port " + port + ".");

# Try to get a cleartext response for our FTP commands over the secure
# (FTPS) channel. Testing revealed that three requests was the minimum
# number required to produce a response, against RhinoSoft Serv-U. So
# we go slightly past that, to give a buffer.
cmd = "FEAT";
features = NULL;
for (i = 0; i < 5; i++)
{
  res = ftp_send_cmd(socket:soc, cmd:cmd);
  if (res && res =~ "^211")
  {
    features = res;
    break;
  }
}

ftp_close(socket:soc);

# Check if we have a response to our request.
if (isnull(features)) audit(AUDIT_LISTEN_NOT_VULN, "FTP server", port);

pci_report = "The FTPs server on port " + port + " allows cleartext connections.";
set_kb_item(name:"PCI/ClearTextCreds/" + port, value:pci_report);

if (report_verbosity > 0)
{
  if (i == 1) s = "";
  else s = "s";

  report =
    '\nThe FTP server responds to cleartext requests on its secure port if SSL' +
    '\nnegotiations fail. For example, by sending the ' + cmd + ' command ' + i + ' time' + s + ', ' +
    '\nNessus was able to generate the following response :' +
    '\n' +
    '\n' + chomp(features) +
    '\n';

  security_warning(port:port, extra:report);
}
else
{
  security_warning(port);
}
