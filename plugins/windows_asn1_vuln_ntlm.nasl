#
# (C) Tenable Network Security, Inc.
#

# Credits to: eEye

include("compat.inc");

if (description)
{
 script_id(12054);
 script_version("$Revision: 1.49 $");
 script_cvs_date("$Date: 2017/02/03 16:29:57 $");

 script_cve_id("CVE-2003-0818");
 script_bugtraq_id(9633, 9635, 9743, 13300);
 script_osvdb_id(3902);
 script_xref(name:"MSFT", value:"MS04-007");

 script_name(english:"MS04-007: ASN.1 Vulnerability Could Allow Code Execution (828028) (uncredentialed check) (NTLM)");
 script_summary(english:"Checks if the remote host has a patched ASN.1 decoder (828028)");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote Windows host has an ASN.1 library that could allow an
attacker to execute arbitrary code on this host.

To exploit this flaw, an attacker would need to send a specially
crafted ASN.1 encoded packet with improperly advertised lengths.

This particular check sent a malformed NTLM packet and determined that
the remote host is not patched." );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms04-007");
 script_set_attribute(attribute:"solution", value:"Microsoft has released patches for Windows NT, 2000, XP, and 2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'MS04-007 Microsoft ASN.1 Library Bitstring Heap Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/10");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/02/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/02/13");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2017 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_require_ports(139,445);
 script_dependencies("netbios_name_get.nasl");
 exit(0);
}

#
include("audit.inc");
include("smb_func.inc");


function mechListMIC()
{
 local_var data;

 data = raw_string(0x30,0x3C,0xA0,0x30,0x3B,0x2E) +
        raw_string(0x04, 0x81, 0x01, 0x25) +
       	raw_string(0x24, 0x81, 0x27) +
        	raw_string(0x04, 0x01, 0x00, 0x24, 0x22, 0x24, 0x20, 0x24,
			   0x18, 0x24, 0x16, 0x24, 0x14, 0x24, 0x12, 0x24,
			   0x10, 0x24, 0x0e, 0x24, 0x0c, 0x24, 0x0a, 0x24,
			   0x08, 0x24, 0x06, 0x24, 0x04, 0x24, 0x02, 0x04,
			   0x00, 0x04, 0x82, 0x00, 0x02, 0x39, 0x25)  +
        	raw_string(0xa1, 0x08) +
       			raw_string(0x04, 0x06) +
				"Nessus";

 return data;
}



#---------------------------------------------------------#
# Function    : ntlmssp_negotiate_securityblob2           #
# Description : Return NTLMSSP_NEGOCIATE blob             #
#---------------------------------------------------------#

function ntlmssp_negotiate_securityblob2 ()
{
 local_var mechtypes, mechtoken, ntlmssp, offset;

 mechtypes = der_encode (tag:0x30, data:der_encode_oid (oid:"1.3.6.1.4.1.311.2.2.10"));

 ntlmssp = "NTLMSSP" + raw_string (0x00);
 ntlmssp += raw_dword (d:1); # NTLMSSP_NEGOTIATE
 ntlmssp += raw_dword (d:NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_NTLM2);  # Flags
 ntlmssp += ntlmssp_data (data:NULL,offset:0); # workstation domain NULL
 ntlmssp += ntlmssp_data (data:NULL,offset:0); # workstation name NULL

 # Version 1.0
 ntlmssp += raw_byte (b:1) + raw_byte (b:0);
 # Version Number = 0
 ntlmssp += raw_word (w:0);

 # Unknown value
 ntlmssp += raw_string (0x00,0x00,0x00,0x0F);

 mechtoken = der_encode_octet_string (string:ntlmssp);

 return der_encode_negtokeninit (mechtypes:mechtypes, reqflags:NULL, mechtoken:mechtoken, mechlistmic:mechListMIC() );
}


os = get_kb_item ("Host/OS/smb") ;
if ("Windows" >!< os) audit(AUDIT_OS_NOT, "Windows");

name = kb_smb_name();
domain = kb_smb_domain();
if(!name)exit(0);

port = int(get_kb_item("SMB/transport"));

if ( ! port )
{
 port = 445;
 soc  = 0;
 if ( get_port_state(port) )
 {
  soc = open_sock_tcp(port);
 }
 if ( ! soc )
 {
  port = 139;
  if ( ! get_port_state(port) ) audit(AUDIT_PORT_CLOSED, port);
 }
}



if ( ! soc ) soc = open_sock_tcp(port);
if ( ! soc ) audit(AUDIT_SOCK_FAIL, port);

session_init (socket:soc, hostname:name);

if ( port == 139 )
{
 if (netbios_session_request () != TRUE)
   exit (0);
}

ret = smb_negotiate_protocol ();
if (!ret)
  exit (0);

# Some checks in the header first
header = get_smb_header (smbblob:ret);
if (!ret)
  exit (0);

if (smb_check_success (data:ret) == FALSE)
  exit (0);

code = get_header_command_code (header:header);
if (code != SMB_COM_NEGOTIATE)
  exit (0);

# We now parse/take information in SMB parameters
parameters = get_smb_parameters (smbblob:ret);
if (!parameters)
  exit (0);

DialectIndex = get_word (blob:parameters, pos:0);

if (DialectIndex > (supported_protocol-1))
  exit (0);

if (protocol[DialectIndex] != "NT LM 0.12")
  exit (0);

SessionKey = get_dword (blob:parameters, pos:15);
Capabilities = get_dword (blob:parameters, pos:19);

if (Capabilities & CAP_UNICODE)
  session_set_unicode (unicode:1);
else
  session_set_unicode (unicode:0);

if (Capabilities & CAP_EXTENDED_SECURITY)
  session_add_flags2 (flag:SMB_FLAGS2_EXTENDED_SECURITY);
else
  exit (0);


header = smb_header (Command: SMB_COM_SESSION_SETUP_ANDX,
                     Status: nt_status (Status: STATUS_SUCCESS));

securityblob = ntlmssp_negotiate_securityblob2 ();

parameters = raw_byte (b:255) + # no further command
             raw_byte (b:0) +
             raw_word (w:0) +
             raw_word (w:session_get_buffersize()) +
             raw_word (w:1) +
             raw_word (w:0) +
             raw_dword (d:SessionKey) +
             raw_word (w:strlen(securityblob)) +
             raw_dword (d:0) +
             raw_dword (d: CAP_UNICODE * session_is_unicode() | CAP_LARGE_FILES | CAP_NT_SMBS | CAP_STATUS32 | CAP_LEVEL_II_OPLOCKS | CAP_NT_FIND | CAP_EXTENDED_SECURITY);

parameters = smb_parameters (data:parameters);

# If strlen (securityblob) odd add 1 pad byte
if ((strlen (securityblob) % 2) == 0)
  securityblob += raw_string(0x00);

data = securityblob +
       cstring (string:"Unix") +
       cstring (string:"Nessus") +
       cstring (string:domain);

data = smb_data (data:data);

packet = netbios_packet (header:header, parameters:parameters, data:data);

ret = smb_sendrecv (data:packet);
if (!ret)
  audit(AUDIT_HOST_NOT, "affected");


# Some checks in the header first
header = get_smb_header (smbblob:ret);
if (!ret)
  audit(AUDIT_HOST_NOT, "affected");

# STATUS_INVALID_PARAMETER -> patched
# STATUS_MORE_PROCESSING_REQUIRED -> vulnerable

code = get_header_nt_error_code(header:header);
if ( code == STATUS_MORE_PROCESSING_REQUIRED) security_hole(port);
else audit(AUDIT_HOST_NOT, "affected");
