# This script was written by William Craig
#
# @DEPRECATED@
exit(0);

if(description)
{
 script_id(12244);
 script_cve_id("CVE-2004-0651");
 script_bugtraq_id(10301);
 script_xref(name:"OSVDB", value:"5984");
 script_version("$Revision: 1.10 $");

 name["english"] = "Sun Java Runtime Environment DoS ";
 script_name(english:name["english"]);

 desc["english"] = "
 The remote Windows machine is running a Java SDK or JRE version
 1.4.2_03 and prior which is vulnerable to a DoS attack.

 Solution: Upgrade to SDK and JRE 1.4.2_04
           http://java.sun.com/j2se/

 Risk factor: High";

 script_description(english:desc["english"]);
 summary["english"] = "Checks for Java SDK and JRE versions prior to 1.4.2_04";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004 Netteksecure Inc. ");
 family["english"]= "Windows";
 script_family(english:family["english"]);
 script_dependencies("netbios_name_get.nasl","smb_login.nasl",
                      "smb_registry_full_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
                     "SMB/registry_full_access");
 script_require_ports(139, 445);
 exit(0);
}

# disabled
exit(0);