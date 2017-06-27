#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25699);
 script_version("$Revision: 1.23 $");
 script_cvs_date("$Date: 2013/11/04 02:28:18 $");

 script_cve_id("CVE-2007-3028", "CVE-2007-0040");
 script_bugtraq_id(24796, 24800);
 script_osvdb_id(35960, 35961);
 script_xref(name:"MSFT", value:"MS07-039");

 script_name(english:"MS07-039: Vulnerability in Windows Active Directory Could Allow Remote Code Execution (926122) (uncredentialed check)");
 script_summary(english:"Determines the presence of update 926122");

 script_set_attribute(attribute:"synopsis", value:"It is possible to execute code on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote version of Active Directory contains a flaw in the LDAP
request handler code that may allow an attacker to execute code
on the remote host.

On Windows 2000, an anonymous attacker can exploit this flaw by
sending a specially crafted LDAP packet.

Additionally, Active Directory is affected by a remote denial of
service vulnerability." );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/MS07-039");
 script_set_attribute( attribute:"solution",  value:"Microsoft has released a set of patches for Windows 2000." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/11");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/07/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/11");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("smb_nativelanman.nasl","ldap_detect.nasl");
 script_require_keys("Host/OS/smb");
 script_require_ports("Services/ldap", 389);
 exit(0);
}

#

include("kerberos_func.inc");
include("ldap_func.inc");

os = get_kb_item ("Host/OS/smb") ;
if ( ! os || "Windows 5.0" >!< os ) exit(0);


port = get_kb_item("Services/ldap");
if (!port) port = 389;

if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

ldap_init(socket:soc);

modification_data =
	der_encode_octet_string (string:"renewServerCertificate") +
	der_encode(tag:0x31, data:der_encode_octet_string (string:"nessus"));

req = ldap_modify_request(object:"", operation:MODIFY_DELETE, data:modification_data);
ret = ldap_request_sendrecv(data:req);

if (isnull(ret) || ret[0] != LDAP_MODIFY_RESPONSE)
  exit(0);

data = ldap_parse_modify_response(data:ret[1]);
if (isnull(data))
  exit(0);

code = data[0];

# Avoid false positives with Active Directory's GC port.
if (
  code == 53 &&
  data[2] &&
  "not allowed through GC port" >< data[2]
) exit(0, "Port "+port+" is a Global Catalog port for Active Directory.");


# renewServerCertificate request support is added by the patch on Windows 2000.
# A vulnerable version returns unwillingToPerform (53) while a patched version
# returns insufficientAccessRights (50)
# Note: Windows 2003 suggests to do a bind first :-)

if (code == 53)
  security_hole(port);
