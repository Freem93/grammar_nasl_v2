#TRUSTED 1614e9c3335a69a6918579a62e57c511c20c67cee60ce5faeae249915ba4b3c5dc340f81ceef552fe075aea9aff00c1b2e772d75a4514128b234181c50dab8ce54777951fd961c01211794458680b1f7aa64ec056c3fbe7fa4a68b500b6899e3e70a7c0b7cc12300aa1c07cdf0f9f22199a59e4ff673600854696fd28d3d1c075c7055938a31eef7aa6d4d26d532858620bc2983ae686e3663539180c354be9dd2905652db84383cc7ed98fcf1360a57830ceb9332467d7371fed9a6d30e23854225f014f1d1fb8f9cda2a302b5511d99b701f3ef982db5c400725e40605709d501d039c682890802b8b6d3ba0288a783004496fd37705be9930da41d75ec63fd19dbbc46cbb2dc2e1174e239cf059005aba01136864cb07e46680186291dcee2e42c34e63696e7e5f3776582485c6544408fa6cf8c1d8bb781fdf394c18a9de63f3c88e78110d6ecc8b11c418d9eeae33fecaac4d506c856e45e7cfbf2d1b6109c66101b8ed4ff6bad96c0eceef869ef04b784e83cf141819ae0c34f74dcd523d22520a964b30ddaec8ad223ff4c62f08f56d0af8cf010755a1b9660e06a0f21bcb0af5c0d4b1d7be74d50994142cfed7fd782f42540b4678c7346e99b368688a9515e13f09703dafe4a0d8d1c7dbfc71a14ef364257cad10e490a2f947cf77639dce1925c5c85fadd61c4a67b4eea15b6ab44a7f71f9c74ee25df6eb7ecb0c
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(32314);
 script_version ("1.15");
 script_set_attribute(attribute:"plugin_modification_date", value:"2015/11/18"); 

 script_cve_id("CVE-2008-0166");
 script_bugtraq_id(29179);
 script_osvdb_id(45029, 45503);

 script_name(english:"Debian OpenSSH/OpenSSL Package Random Number Generator Weakness");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SSH host keys are weak." );
 script_set_attribute(attribute:"description", value:
"The remote SSH host key has been generated on a Debian 
or Ubuntu system which contains a bug in the random number
generator of its OpenSSL library.

The problem is due to a Debian packager removing nearly all
sources of entropy in the remote version of OpenSSL.

An attacker can easily obtain the private part of the remote
key and use this to set up decipher the remote session  or
set up a man in the middle attack." );
 script_set_attribute(attribute:"solution", value:
"Consider all cryptographic material generated on the remote host
to be guessable. In particuliar, all SSH, SSL and OpenVPN key
material should be re-generated." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d01bdab" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f14f4224" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(310);
	
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/05/14");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
 
 script_summary(english:"Checks for the remote SSH public key fingerprint");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");

 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}


include("byte_func.inc");
include("ssh_func.inc");

SSH_RSA = 0;
SSH_DSS = 1;



function file_read_dword(fd)
{
 local_var dword;

 dword = file_read(fp:fd, length:4);
 dword = getdword(blob:dword, pos:0);

 return dword;
}


function find_hash_list(type, first, second)
{
 local_var list, fd, i, j, main_index, sec_index, c, offset, length, len, pos, file;
 local_var tmp_list;

 if (type == SSH_RSA)
   file = "blacklist_rsa.inc";
 else if (type == SSH_DSS)
   file = "blacklist_dss.inc";

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

ports = get_kb_list("Services/ssh");
if (isnull(ports)) ports = make_list(22);
else ports = make_list(ports);

foreach port (ports)
{
  fingerprint = get_kb_item("SSH/Fingerprint/ssh-rsa/"+port);
  if (fingerprint)
  {
    ret = is_vulnerable_fingerprint(type:SSH_RSA, fp:substr(ssh_hex2raw(s:fingerprint), 6, 15));
    if (ret)
    {
      security_hole(port);
      exit(0);
    }
  }

  fingerprint = get_kb_item("SSH/Fingerprint/ssh-dss");
  if (fingerprint)
  {
    ret = is_vulnerable_fingerprint(type:SSH_DSS, fp:substr(ssh_hex2raw(s:fingerprint), 6, 15));
    if (ret)
    {
      security_hole(port);
      exit(0);
    }
  }
}
