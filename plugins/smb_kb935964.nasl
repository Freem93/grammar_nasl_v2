#
# (C) Tenable Network Security, Inc.
#

# @DEPRECATED@
#
# This script has been disabled and the code intended to be blank.
# Disabled on 2007/05/09. 
exit(0);

if(description)
{
 script_id(25035);
 script_version("$Revision: 1.11 $");
 script_cve_id("CVE-2007-1748");
 script_bugtraq_id(23470);
 script_xref(name:"OSVDB", value:"34100");

 script_name(english:"MS07-029: Microsoft Windows DNS RPC Interface Zone Name Remote Overflow (935964)");
 
 desc["english"] = "Synopsis :

Arbitrary code can be executed on the remote host due to the DNS service.

Description :

The remote host has the Windows DNS server installed.

There is a flaw in the remote version of this server which may allow an
attacker to execute arbitrary code on the remote host with SYSTEM
privileges. To exploit this flaw, an attacker needs to connect to the
DNS server RPC interface and send malformed RPC queries.

Solution : 

Microsoft has released the security advisory 935964 detailing 
a method to disable the RPC interface of the remote service.

Apply this workaround until Microsoft releases a patch for this
issue.

See also :

http://technet.microsoft.com/en-us/security/bulletin/ms07-029
http://technet.microsoft.com/en-us/security/advisory/935964

Risk factor : 

Critical / CVSS Base Score : 10.0
(CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C)";

 script_description(english:desc["english"]);
 script_summary(english:"Checks if the MS DNS server has its RPC interface enabled");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 script_dependencies("dcetest.nasl", "smb_nativelanman.nasl");
 script_require_keys("Host/OS/smb", "Services/DCE/50abc2a4-574d-40b3-9d66-ee4fd5fba076");
 exit(0);
}


