#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40887);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2017/04/19 13:27:09 $");

  script_cve_id("CVE-2009-2532", "CVE-2009-3103");
  script_bugtraq_id(36299, 36594);
  script_osvdb_id(57799, 58876);
  script_xref(name:"MSFT", value:"MS09-050");
  script_xref(name:"CERT", value:"135940");
  script_xref(name:"EDB-ID", value:"9594");
  script_xref(name:"EDB-ID", value:"10005");
  script_xref(name:"EDB-ID", value:"12524");
  script_xref(name:"EDB-ID", value:"14674");
  script_xref(name:"EDB-ID", value:"16363");

  script_name(english:"MS09-050: Microsoft Windows SMB2 _Smb2ValidateProviderCallback() Vulnerability (975497) (EDUCATEDSCHOLAR) (uncredentialed check)");
  script_summary(english:"Determines if the remote host is affected by a SMBv2 vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be executed on the remote host through the SMB
port");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Windows Vista or
Windows Server 2008 that contains a vulnerability in its SMBv2
implementation. An attacker can exploit this flaw to disable the
remote host or to execute arbitrary code on it.

EDUCATEDSCHOLAR is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2017/04/14 by a group known as the Shadow
Brokers.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f72ec72");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/MS09-050");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Windows Vista and Windows Server
2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS09-050 Microsoft SRV2.SYS SMB Negotiate ProcessID Function Table Dereference');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_require_ports(139, 445);
  exit(0);
}

#

include("smb_func.inc");

port = 445;
if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
session_set_socket(socket:soc);


#---------------------------------------------------------#
# struct {                                                #
#   BYTE  Protocol[4];      # "\xFFSMB"                   #
#   BYTE  Command;                                        #
#   DWORD Status;           # Or BYTE ErrorClass;         #
#                           #    BYTE Reserved;           #
#                           #    WORD Error;              #
#   BYTE  Flags;                                          #
#   WORD  Flags2;                                         #
#   WORD  PidHigh;          			          #
#   BYTE  Signature[8];                                   #
#   WORD  Reserved;                                       #
#   WORD  Tid;              # Tree ID                     #
#   WORD  Pid;              # Process ID                  #
#   WORD  Uid;              # User ID                     #
#   WORD  Mid;              # Multiplex ID                #
# }                                                       #
#---------------------------------------------------------#


header = '\xFFSMB';
header += raw_byte(b:SMB_COM_NEGOTIATE);
header += nt_status(Status:STATUS_SUCCESS);
header += raw_byte (b:0x18);
header += raw_word (w:0xc853);
header += raw_word(w:0x0001); # Process ID high
header += raw_dword (d:session_get_sequencenumber()) + raw_dword (d:0);
header += raw_word (w:0);
header += raw_word (w:session_get_tid());
header += raw_word (w:session_get_pid());
header += raw_word (w:session_get_uid());
header += raw_word (w:session_get_mid());

parameters = smb_parameters(data:NULL);

ns = supported_protocol;

protocol[0] = "TENABLE_NETWORK_SECURITY";
data = NULL;
for (i = 0; i < ns; i++)
  data += raw_byte (b:0x02) + ascii (string:protocol[i]);
data = smb_data (data:data);


packet = netbios_packet (header:header, parameters:parameters, data:data);

r = smb_sendrecv(data:packet);
close(soc);

if ( !isnull(r) && "ORK_SECURITY" >< r )
	security_hole(port);
else exit(0, "The remote host is not vulnerable to this flaw");
