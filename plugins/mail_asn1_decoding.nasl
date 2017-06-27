#
# (C) Tenable Network Security, Inc.
#

#
# Thanks to Juliano Rizzo <juliano@corest.com> for suggesting to do
# the check using SMTP NTLM authentication.
#
# Credit for the original advisory and blob : eEye
#

include("compat.inc");

if (description)
{
 script_id(12065);
 script_version("$Revision: 1.36 $");
 script_cvs_date("$Date: 2016/11/28 21:06:39 $");
 script_bugtraq_id(9633, 9635, 9743, 13300);
 script_osvdb_id(3902);
 script_xref(name:"MSFT", value:"MS04-007");
 script_cve_id("CVE-2003-0818");

 script_name(english:"ASN.1 Multiple Integer Overflows (SMTP check)");
 script_summary(english:"Checks if the remote host has a patched ASN.1 decoder (828028)");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote host has multiple integer overflow vulnerabilities."
 );
 script_set_attribute( attribute:"description", value:
"The remote Windows host has an ASN.1 library with multiple integer
overflow vulnerabilities.  These issues could lead to a heap-based
buffer overflow.  A remote attacker could exploit these issues to
execute arbitrary code.

This particular check sent a malformed SMTP authorization packet and
determined that the remote host is not patched." );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms04-007");
 script_set_attribute(
   attribute:"solution",
   value:
"Microsoft has released a set of patches for Windows NT, 2000, XP, and
2003."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'MS04-007 Microsoft ASN.1 Library Bitstring Heap Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/10");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/02/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/02/18");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"SMTP problems");

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

 script_require_ports("Services/smtp", 25);
 script_dependencies("smtpserver_detect.nasl", "smtpscan.nasl");

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");


function gssapi(oid, spenego)
{
 local_var len;
 len = strlen(oid) + strlen(spenego);
 return raw_string(0x60, 0x84,0,0,0,len % 256) + oid + spenego;
}

# Returns SPNEGO OID (1.3.6.5.5.2)
function oid()
{
 local_var oid, len;
 oid = raw_string(0x2b, 0x06, 0x01, 0x05, 0x05, 0x02);
 len = strlen(oid);
 return raw_string(0x06, 0x83,0,0,len % 256) + oid;
}


# ANS.1 encodes our negTokenInit blob
function spenego(negTokenInit)
{
 local_var len;
 len = strlen(negTokenInit);

 return raw_string(0xa0, 0x82,0,len % 256) + negTokenInit;
}


# ASN.1 encodes our mechType and mechListMIC
function negTokenInit(mechType, mechListMIC)
{
 local_var len, len2, data, data2;

 len = strlen(mechType);
 data = raw_string(0xa0, len + 2, 0x30, len);
 len += strlen(data) + strlen(mechListMIC) + 8;

 len2 = strlen(mechListMIC);
 data2 = raw_string(0xa3, len2 + 6, 0x30, len2 + 4, 0xa0, len2 - 8 , 0x3b, 0x2e);


 return raw_string(0x30,0x81,len % 256) + data + mechType + data2 + mechListMIC;
}

# Returns OID 1.3.6.1.4.1.311.2.2.10 (NTMSSP)
function mechType()
{
 return raw_string(0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a);
}

function mechListMIC()
{
 local_var data;

 data = raw_string(0x04, 0x81, 0x01, 0x25) +
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




port = get_kb_item("Services/smtp");
if ( ! port ) port = 25;
if ( ! get_port_state(port) ) exit(0);


sig = get_kb_item("smtp/" + port + "/real_banner");
if (! sig ) sig = get_smtp_banner(port:port);

if ( sig && "Microsoft" >!< sig ) exit(0);


blob = base64(str:gssapi(oid:oid(), spenego:spenego(negTokenInit:negTokenInit(mechType:mechType(), mechListMIC:mechListMIC()))));

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
smtp_recv_line(socket:soc);
send(socket:soc, data:'EHLO there\r\n');
smtp_recv_line(socket:soc);
send(socket:soc, data:'AUTH GSSAPI\r\n');
r = smtp_recv_line(socket:soc);
if ( egrep(pattern:"^334 .*", string:r) )
{
 send(socket:soc, data:blob + '\r\n');
 r = smtp_recv_line(socket:soc);
 if ( egrep(pattern:"^334 .*", string:r ) ) { security_hole(port); }
}

close(soc);
