#TRUSTED 49d021387fe1dd272514f384f391f50fa790580be5040c8c9800175639ddcc02f83e9f84abb8e5920b3366949feba8b2307b48ea6c5329b8a82f240ce9f09f7bee1b2e69d5e0877ebde3f814c6a44ec526d45fa8ff715505ba67a41c2fcaa049d53e3339055f824d6d64c1f1ac0e06e008f9028bf4059d9d0cbe618ad0882cc743be508a1b3b748c5cbabf9d4dfd4b7a265a614fbcdddad9e6104496bd924dee59a0846f6e161d8b5fa7b80646f99658c1e28abfbd218c53fc14720da76cf55091f783289730d7866ad9bcef660f3d05e82780cff7829146f26b295de56a8add2243d2b047d2d30d42f854dcbf3b7e483558c8f07f09bddf680975d5f0dc52676af16b32988c632fc028af1dcfda2fc7a446fee40c645ed8b057f2b2fde59519733bd8ade40aa2cb074e7348ba55203984d4b95158c05e51806ea405053d9ff91b3f1beee2798ee0ab6d0e3a44ba1e1f059617e4fa4c1ef137b64e6639239c45b243ac1303fe00d72131134c9185a2c21360bbecc40a132cec681f0603e95d368c31af402dabe86665a438c1c248f5aa0e83eb33338d9d33a6b01424fd3f8c4f8e53128b6712968d9f230be2922b90d0b01327ae848469a31b775dd4d85e399cacc27e5fcfa28f2871fba7f0156b9af3f712895314eacb44f8b69f8a376700c3da956be4082f741ea6d09f18ff9334df96fc8bd8df71c3955c2f3f387132d324
#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3000 ) exit(0);

include("compat.inc");

if (description)
{
 script_id(32321);
 script_version("1.21");
 script_set_attribute(attribute:"plugin_modification_date", value:"2015/10/07");

 script_cve_id("CVE-2008-0166");
 script_bugtraq_id(29179);
 script_osvdb_id(45029, 45503);

 script_name(english:"Debian OpenSSH/OpenSSL Package Random Number Generator Weakness (SSL check)");
 script_summary(english:"Checks for the remote SSL public key fingerprint");

 script_set_attribute(attribute:"synopsis", value:"The remote SSL certificate uses a weak key.");
 script_set_attribute(attribute:"description", value:
"The remote x509 certificate on the remote SSL server has been generated
on a Debian or Ubuntu system which contains a bug in the random number
generator of its OpenSSL library. 

The problem is due to a Debian packager removing nearly all sources of
entropy in the remote version of OpenSSL. 

An attacker can easily obtain the private part of the remote key and use
this to decipher the remote session or set up a man in the middle
attack.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d01bdab");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f14f4224");
 script_set_attribute(attribute:"solution", value:
"Consider all cryptographic material generated on the remote host to be
guessable.  In particuliar, all SSH, SSL and OpenVPN key material should
be re-generated.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(310);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/05/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/05/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/15");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"in_the_news", value:"true");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");

 script_dependencies("ssl_supported_versions.nasl");
 script_require_keys("SSL/Supported");

 exit(0);
}

include("global_settings.inc");
include("x509_func.inc");

RSA_1024 = 0;
RSA_2048 = 1;

function file_read_dword(fd)
{
 local_var dword;

 dword = file_read(fp:fd, length:4);
 dword = getdword(blob:dword, pos:0);

 return dword;
}


function find_hash_list(type, first, second)
{
 local_var list, fd, i, j, main_index, sec_index, c, offset, length, len, pos, file, tmp_list;

 if (type == RSA_1024)
   file = "blacklist_ssl_rsa1024.inc";
 else if (type == RSA_2048)
   file = "blacklist_ssl_rsa2048.inc";

 if ( ! file_stat(file) ) return NULL;

 fd = file_open(name:file, mode:"r");
 if (!fd) return NULL;

 main_index = file_read_dword(fd:fd);

 for (i=0; i<main_index; i++)
 {
  c = file_read(fp:fd, length:1);
  offset = file_read_dword(fd:fd);
  length = file_read_dword(fd:fd);

  if (c == first)
  {
   file_seek(fp:fd, offset:offset);
   sec_index = file_read_dword(fd:fd);

   for (j=0; j<sec_index; j++)
   {
    c = file_read(fp:fd, length:1);
    offset = file_read_dword(fd:fd);
    length = file_read_dword(fd:fd);

    if (c == second)
    {
     file_seek(fp:fd, offset:offset);
     tmp_list = file_read(fp:fd, length:length);

     len = strlen(tmp_list);
     pos = 0;

     for (j=0; j<len; j+=10)
       list[pos++] = substr(tmp_list, j, j+9);

     break;
    }
   }

   break;
  }
 }

 file_close(fd);

 return list;
}

function is_vulnerable_fingerprint(type, fp)
{
 local_var list, i, len;

 list = find_hash_list(type:type, first:fp[0], second:fp[1]);
 if (isnull(list))
   return FALSE;

 len = max_index(list);

 for (i=0; i<len; i++)
   if (list[i] == fp)
     return TRUE;

 return FALSE;
}

get_kb_item_or_exit("SSL/Supported");

port = get_ssl_ports(fork:TRUE);
if (isnull(port)) exit(1, "The host does not appear to have any SSL-based services.");

if (!get_port_state(port)) exit(0, "Port " + port + " is not open.");

cert = get_server_cert(port:port, encoding:"der");
if (isnull(cert)) exit(1, "Failed to read the certificate for the service listening on port "+port+".");

key = parse_der_cert(cert:cert);
if (isnull(key)) exit(1, "Failed to parse the certificate from the service listening on port "+port+".");

key = key['tbsCertificate'];
key = key['subjectPublicKeyInfo'];
key = key[1];
key = key[0];

if(isnull(key)) exit(1, "Failed to extract public key in the certificate from the service listening on port "+port+".");

bits = der_bit_length(key);
if (bits == 2048)
  type = RSA_2048;
else if(bits == 1024)
  type = RSA_1024;
else exit(1, "Unsupported public key length in the certificate from the service listening on port "+port+".");

while (strlen(key) > 0 && ord(key[0]) == 0)
  key = substr(key, 1, strlen(key)-1);

if (strlen(key) == 0) exit(1, "Failed to parse the key from the certificate from the service listening on port "+port+".");

mod = "Modulus=" + toupper(hexstr(key)) + '\n';

hex = substr(SHA1(mod), 0, 9);

ret = is_vulnerable_fingerprint(type:type, fp:hex);
if (ret) security_hole(port);
