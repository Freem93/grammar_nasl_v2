#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87734);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/01/05 18:44:51 $");

  script_name(english:"SMB Password Encryption Not Required");
  script_summary(english:"Checks if the remote SMB server requires password encryption.");

  script_set_attribute(attribute:"synopsis", value:
"Password encryption is not required on the remote SMB server.");
  script_set_attribute(attribute:"description", value:
"The remote SMB server does not require password encryption. This
allows clients to send cleartext passwords over the network.");
  script_set_attribute(attribute:"solution", value:
"Require password encryption on the SMB server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/05");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/smb", 139, 445);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("byte_func.inc");

# Get the smb port
port = kb_smb_transport();
if (!port) port = 139;

# Ensure the port is open.
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

# Open a socket
s = open_sock_tcp(port);
if (!s) audit(AUDIT_SOCK_FAIL, port);

# Send the SMB_COM_NEGOTIATE packet
session_init(socket:s);
result = smb_negotiate_protocol(extended:TRUE);

close(s);

if (isnull(result)) audit(AUDIT_RESP_BAD, port);

# SMBv1 Only Affected
if(result[0] != '\xFF') audit(AUDIT_HOST_NOT, 'affected');

# Get the parameters section of the packet
parameters = get_smb_parameters(smbblob:result);
if (isnull(parameters)) audit(AUDIT_RESP_BAD, port);

# Get the security mode (this is the same in every SMB version)
security_mode = getbyte(blob:parameters, pos:0x02);

if (isnull(security_mode)) audit(AUDIT_RESP_BAD, port);

# Check if password encryption is required
if (!(security_mode & 0x02))
{
  pci_report = 'The remote SMB service has password encryption disabled.';
  set_kb_item(name:"PCI/ClearTextCreds/" + port, value:pci_report);

  security_warning(port);
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
