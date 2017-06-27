#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90941);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/07 18:40:29 $");

  script_cve_id("CVE-2016-2004");
  script_osvdb_id(137516);
  script_xref(name:"HP",value:"emr_na-c05085988");
  script_xref(name:"HP",value:"HPSBGN03580");
  script_xref(name:"HP",value:"SSRT102163");
  script_xref(name:"HP",value:"PSRT102293");
  script_xref(name:"CERT",value:"267328");

  script_name(english:"HP Data Protector Hard-coded Cryptographic Key (HPSBGN03580)");
  script_summary(english:"Checks the server public key.");

  script_set_attribute(attribute:"synopsis",value:
"An application running on the remote host utilizes an embedded SSL
private key.");
  script_set_attribute(attribute:"description",value:
"The HP Data Protector application running on the remote host contains
an embedded SSL private key that is shared across all installations.
An attacker can exploit this to perform man-in-the-middle attacks
against the host or have other potential impacts.");
  #http://h20565.www2.hpe.com/hpsc/doc/public/display?calledBy=&docId=emr_na-c05085988 
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?b20bcde7");
  script_set_attribute(attribute:"see_also",value:"http://www.kb.cert.org/vuls/id/267328");
  script_set_attribute(attribute:"solution",value:
"Apply the appropriate patch according to the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP Data Protector Encrypted Communication Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/04/22");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:hp:data_protector");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/hp_openview_dataprotector", 5555);
  script_dependencies("hp_data_protector_installed.nasl");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("x509_func.inc");
include("dump.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Make sure hpdp is detected
port = get_service(svc:'hp_openview_dataprotector', exit_on_fail:TRUE);

soc = open_sock_tcp(port);
if (!soc)
  audit(AUDIT_SOCK_FAIL, port);

function inet_recv(soc)
{
  local_var data, len;

  # Read 4-byte packet length
  data = recv(socket:soc, length: 4, min:4);
  if(strlen(data) != 4)
    return NULL;

  # Check packet length 
  len = getdword(blob: data, pos:0);
  if(len > 1024 * 1024)
    return NULL;
     
  # Read the remaining packet data
  data += recv(socket:soc, length: len, min: len);
  if(strlen(data) != len + 4)
    return NULL; 
 
  return data; 
}

function getstr(blob, pos, bom)
{
  local_var c, cp, cn, cs, s, len;

  len = strlen(blob);
  if (bom == '\xff\xfe' || bom == '\xfe\xff')
  {
    if(len % 2) return NULL;

    cs = 2;
    cn = '\x00\x00';
    if(bom =='\xff\xfe')
      cp = 0;
    else
      cp = 1; 
  }
  else
  {
    cs = 1; 
    cp = 0;
    cn = '\x00';
  }
 
  s = NULL; 
  while(pos + cs <= len)
  {
    c = substr(blob, pos, pos + cs - 1);
    if (c == cn)
      break;
  
    s += c[cp];
    pos += cs;
  }

  return s;
}

function utf16(be)
{ 
  local_var i, in, out;
 
  in = _FCT_ANON_ARGS[0];

  if( isnull(in)) return NULL;
 
  out = NULL;
  for (i = 0; i < strlen(in); i++)
  {
    if(be)
      out += '\x00' + in[i];
    else
      out += in[i] + '\x00';
  } 

  # NULL-terminate the string  
  out += '\x00\x00';    

  return out;
}

function status()
{
  local_var err, data, ret;

  err  = _FCT_ANON_ARGS[0];
  data = _FCT_ANON_ARGS[1];

  ret[0] = err;
  ret[1] = data;

  return ret;
}

function parse_proto_info()
{
  local_var data, err, len, marker, ret;
  local_var bom, cn, cs, field, i, sp, pos;

  data = _FCT_ANON_ARGS[0];

  len = strlen(data);

  if(len < 6)
    return status('Invalid response packet length');

  pos = 4; # Skip 4-byte pkt length
  bom = substr(data, pos, pos + 1);

  if(bom == '\xff\xfe' || bom == '\xfe\xff')
  {
    cn = '\x00\x00';
    cs = strlen(cn);
    if(bom == '\xff\xfe')
      sp = '\x20\x00';
    else
      sp = '\x00\x20';

    pos += 2;
  }
  else
  {
    bom = NULL;
    cn = '\x00';
    cs = strlen(cn);
    sp = '\x20';
  }
    
  i = 0;
  repeat 
  {
    field = getstr(blob: data, pos: pos, bom: bom); 
    if(! field) 
      return status('Failed to get a string at position ' + pos); 

    ret[i++] = field;

    # Advance to next string
    pos += (strlen(field) + 1) * cs;

    # Get field seperator/marker 
    if (pos + cs <= len)
    {
      marker = substr(data, pos, pos + cs -1);
      if( marker != sp && marker != cn)
        return status('Invalid field separator at position ' + pos);

      pos += cs;
    }
    else
      return status('Failed to get a field separator at position ' + pos);
         
  } until (marker == cn);

  return status(NULL, ret);
  
}  

req = '\xff\xfe' +
      utf16('267') +  # MSG_PROTOCOL 
      utf16(' 10') +  # protocol type 
      utf16(' 100') + # protocol version
      utf16(' 900') + # module version 
      utf16(' 88') +  # module subversion 
      utf16(' NESSUS') + # 
      utf16(' 4') +   # protocol flags 
      utf16('');

req = mkdword(strlen(req)) + req;
send(socket: soc, data: req); 
      
res = inet_recv(soc:soc);
if (! res)
  audit(AUDIT_RESP_NOT, port, 'an HP Data Protector request');

ret = parse_proto_info(res);
if(ret[0])
  exit(1, 'Failed to parse response received from port ' + port +': ' + ret[0] + '.');

proto_flags = ret[1][6];
if(isnull(proto_flags))
  exit(1, 'Failed to get protocol flags in response received from service listening on port '+ port + '.');

flags = uint(proto_flags);

if(!(flags & 0x4))
 exit(1, 'The service listening on port '+ port + ' does not appear to have enabled encryption. Protocol flags: ' + proto_flags +'.'); 
  
# HP DP is known to support TLSv1.0
cert = get_server_cert(port: port, socket: soc, encaps:ENCAPS_TLSv1, encoding:"der");
close(soc);

if (isnull(cert))
{
  exit(1, 'Failed to get server certificate for service listening on port ' + port +'.');
}
cert = parse_der_cert(cert:cert);
if (isnull(cert))
{
  exit(1, 'Failed to parse server certificate for service listening on port ' + port +'.');
}

cert = cert['tbsCertificate'];
n = cert['subjectPublicKeyInfo'][1][0];
e = cert['subjectPublicKeyInfo'][1][1];
if(isnull(n) || isnull(e))
{
  exit(1, 'Failed to extract RSA public key from certificate for service listening on port ' + port +'.');
}

fixed_n = raw_string(
  0x00, 0xA9, 0xC7, 0xD1, 0xA3, 0xBA, 0x5A, 0x84, 
  0xB3, 0xCA, 0x1D, 0xBB, 0x63, 0xA2, 0x4F, 0x6E,
  0x45, 0x88, 0xF6, 0x01, 0x20, 0xE3, 0xDD, 0x2C, 
  0xAA, 0x66, 0x87, 0x0A, 0x0A, 0x77, 0xC1, 0xB7, 
  0x00, 0x52, 0x24, 0xD0, 0x43, 0xD8, 0xAB, 0x27,
  0x60, 0x14, 0xC5, 0x97, 0xEF, 0x8C, 0x5E, 0x31,
  0x23, 0xB2, 0xA8, 0x46, 0x95, 0x6C, 0xA0, 0x06,
  0x04, 0x12, 0x13, 0xE3, 0x53, 0x85, 0x4D, 0x46,
  0xD1 
);
fixed_d = raw_string(
  0x00, 0x96, 0x26, 0x20, 0x51, 0xC3, 0x12, 0x20,
  0x7F, 0xFC, 0x44, 0x95, 0x1F, 0xC5, 0x40, 0xA8,
  0x0E, 0x18, 0xD5, 0x2F, 0x24, 0x4E, 0x40, 0xA1,
  0x2A, 0xC5, 0xE7, 0xB1, 0x4A, 0x96, 0xA4, 0x9B,
  0xD8, 0xDD, 0x08, 0x3A, 0xCB, 0x95, 0x7F, 0xC5,
  0x7D, 0xAB, 0x9F, 0x9A, 0x82, 0x29, 0xF8, 0x55,
  0x3E, 0x1E, 0xE6, 0x9D, 0xDD, 0x3B, 0x96, 0x92,
  0xF3, 0xFE, 0x43, 0xD5, 0x1D, 0x15, 0xD9, 0x2B,
  0xED
);

if(e == '\x01\x00\x01' && n == fixed_n)
{
  report =  
    'Nessus detected the following RSA modulus : ' + 
    '\n' +
    '\n' + hexdump(ddata:fixed_n) +
    '\nwith its corresponding private exponent being : '+
    '\n' + hexdump(ddata:fixed_d)+ 
    '\nwhich appears to be shared among multiple HP Data Protector installations.';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else
  audit(AUDIT_HOST_NOT, 'affected');
  
