#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33900);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2008-3703");
  script_bugtraq_id(30596);
  script_osvdb_id(47473);
  script_xref(name:"TRA", value:"TRA-2008-01");
  script_xref(name:"Secunia", value:"31486");

  script_name(english:"VERITAS Storage Foundation NULL NTLMSSP Authentication Bypass (SYM08-015)");
  script_summary(english:"Checks for presence of SYM08-015"); 
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The version of the Scheduler Service component installed as part of
Veritas Storage Foundation for Windows on the remote host allows NULL
NTLMSSP authentication.  If requests can be sent to the TCP service
listening on port 4888, a remote attacker can leverage this issue
to add, modify, or delete snapshot schedules and consequently to run
arbitrary code on the affected host under the context of the SYSTEM
user." );
 script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2008-01");
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-053" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/495487/30/0/threaded" );
  # http://securityresponse.symantec.com/avcenter/security/Content/2008.08.14a.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?492d2101" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch as discussed in the vendor's advisory." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(287);
 script_set_attribute(attribute:"vuln_publication_date", value: "2008/08/14");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/08/14");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/15");
 script_cvs_date("$Date: 2016/05/09 15:53:03 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:veritas_storage_foundation");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_dependencies("veritas_storage_foundation_dos.nasl", "veritas_storage_foundation_bypass.nasl"); # service seems fragile for version 5.0
  script_require_keys("VERITAS/VeritasSchedulerService");
  script_require_ports(4888);

  exit(0);
}


include ("raw.inc");
include ("smb_func.inc");
include ("audit.inc");

global_var enc_arcS, enc_arcS2, enc_i, enc_j;


function initialize_key (key, constant)
{
 return MD5 (
	key +
	constant +
	raw_string(0)  # NULL end char
	);
};

function arcfour_enc_setkey (key)
{
 local_var i,j,temp;

 enc_arcS = NULL;
 for (i=0; i < 256; i++)
 {
  enc_arcS[i] = i;
  enc_arcS2[i] = ord(key[i % strlen(key)]);
 }

 j = 0;
 
 for (i=0; i < 256; i++)
 {
  j = (j + enc_arcS[i] + enc_arcS2[i]) % 256;
  temp = enc_arcS[i];
  enc_arcS[i] = enc_arcS[j];
  enc_arcS[j] = temp;
 }

 enc_i = enc_j = 0;
}


function arcfour_encrypt (data)
{
 local_var temp,t,k,output,l;

 output = NULL;
 
 for (l=0; l < strlen(data); l++)
 {
  enc_i = (enc_i+1) % 256;
  enc_j = (enc_j + enc_arcS[enc_i]) % 256;
  temp = enc_arcS[enc_i];
  enc_arcS[enc_i] = enc_arcS[enc_j];
  enc_arcS[enc_j] = temp;
  t = (enc_arcS[enc_i] + enc_arcS[enc_j]) % 256;
  k = enc_arcS[t];

  output += raw_string (k ^ ord(data[l]));
 }

 return output;
}


function initialize_ntlmssp_null()
{
 local_var key, keys;
 local_var ctssign, stcsign;
 local_var ctsseal, stcseal;

 key = crap(data:'\0', length:0x10);

 ctssign = initialize_key (key:key, constant:"session key to client-to-server signing key magic constant");
 stcsign = initialize_key (key:key, constant:"session key to server-to-client signing key magic constant");

 key = crap(data:'\0', length:0x5);

 ctsseal = initialize_key (key:key, constant:"session key to client-to-server sealing key magic constant");
 stcseal = initialize_key (key:key, constant:"session key to server-to-client sealing key magic constant");

 keys = mklist (ctssign, stcsign, ctsseal, stcseal);

 return keys;
}


function sched_sendrecv(socket, code, guid, data)
{
 local_var len;

 len = strlen(data);

 data = 
	mkdword(len) +
	mkdword(code) +
	mkdword(0) +
        guid +
	mkbyte(0) +
	data;

 send(socket:socket, data:data);
 data = recv(socket:socket, length:51, min:51);
 if (strlen(data) < 51)
   return NULL;

 len = getdword(blob:data, pos:0);
 if (len > 10000)
   return NULL;

 code = getdword(blob:data, pos:4);
 data = recv(socket:socket, length:len);

 return mklist(code,data);
}


port = get_kb_item("VERITAS/VeritasSchedulerService");
if (!port) port = 4888;

if (!get_port_state(port))
  audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

req = ntlmssp_negotiate_securityblob();
if(isnull(req))
  exit(1, 'Failed to create a NTLMSSP_NEGOTIATE message.');

# Send NTLMSSP_NEGOTIATE and wait for a response 
ret = sched_sendrecv(socket:soc, code:0x10, guid:"{c15f4527-3d6c-167b-f9c2-ca3908613b5a}", data:req);
if (isnull(ret)) 
  exit(1, "Failed to receive to a proper Veritas Scheduler message."); 

# Check response 
code = ret[0];
data = ret[1];

# VxSchedService.exe 5.0.0.297 doesn't support ntlmssp auth,
# so it's vulnerable to registry manipulations. 
if( code == 0x18)
{
  if ("-2147220973" >< data)
  {
    exit(0, 'The service listening on port ' + port + ' does not appear to ' +
      'support authentication, so it is vulnerable to registry manipulations. '+
      'It is strongly recommended that the software be upgraded.');  
  }
     
}
else 
{
  if (code != 0x20)
    audit(AUDIT_RESP_BAD, port, 'a NTLMSSP_NEGOTIATE message.'); 
}

ret = ntlmssp_parse_challenge(data:data);
if (isnull(ret)) exit(1, 'Failed to parse a NTLMSSP_CHALLENGE message');

nd = ntlmssp_auth_securityblob();

# Comment out: RC4 encryption is not used
#keys = initialize_ntlmssp_null();
#sid = 0;
#arcfour_enc_setkey (key:keys[2]);
#arcfour_dec_setkey (key:keys[3]);

req = nd[1];
if(isnull(req))
  exit(1, 'Failed to create a NTLMSSP_AUTHENTICATION message.');

filter = "src host " + get_host_ip() + " and src port " + port + " and dst port " + get_source_port(soc) + " and tcp";
bpf = bpf_open(filter);
if(! bpf) audit(AUDIT_FN_FAIL, 'bpf_open');
srv_close = FALSE;

# Send NTLMSSP_AUTHENTICATION with NULL credentials
# and wait for a response
ret = sched_sendrecv(socket:soc, code:0x10, guid:"{c15f4527-3d6c-167b-f9c2-ca3908613b5a}", data:req);

# For both vulnerable and patched servers, AcceptSecurityContext() should 
# return SEC_E_OK
if (isnull(ret))
  audit(AUDIT_RESP_NOT, port, 'a NTLMSSP_AUTHENTICATION message'); 
 
if(ret[0] != 0x20 || isnull(ret[1]))
  audit(AUDIT_RESP_BAD, port, 'a NTLMSSP_AUTHENTICATION message'); 

ret = ntlmssp_parse_response(data:ret[1]);
if (!isnull(ret) && (ret == 0)) # Accept Completed
{

 # Collect packets for a period of time 
 pkts = make_list(); 
 i = 0;
 then = unixtime(); 
 repeat {
    ret = bpf_next(bpf:bpf);  
    if(ret) pkts[i++] = ret;
 } until((unixtime() - then) >= 5);

 if(max_index(pkts) < 1) exit(1, 'No packets captured.');

 # Check if server closed the connection
 foreach p (pkts)
 {
   ret = substr(p, strlen(link_layer())); 
   pkt = packet_split(ret);
   tcp = pkt[1];

   tcp = tcp["data"];
   if ((tcp["th_flags"] & (TH_FIN|TH_RST )))
   {
    srv_close = TRUE;
    break;
   }
 } 

 # After a NULL session is established, the vulnerable server
 # waits for more incoming messages, so it doesn't close the connection  
 if(! srv_close) security_hole(port);
 # Patched server checks if the established session is a NULL session,
 # if it is, it closes the connection
 else audit(AUDIT_HOST_NOT, 'affected');
}
else exit(1, 'Nessus could not establish a NULL NTLMSSP session with remote host.');
