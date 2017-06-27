#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19589);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2005-2770", "CVE-2005-2771");
  script_bugtraq_id(14733, 14734, 14735);
  script_osvdb_id(19265, 19266, 19267);

  name["english"] = "AttachmateWRQ Reflection for Secure IT Server < 6.0 Build 24 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SSH server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running AttachmateWRQ Reflection for Secure IT
Server, a commercial SSH server for Windows. 

According to its banner, the installed version of Reflection for
Secure IT Server on the remote host suffers from several
vulnerabilities, including :

  - An Access Restriction Bypass Vulnerability
    Access expressions are evaluated in a case-sensitive
    manner while in versions prior to 6.0 they were case-
    insensitive. This may let an attacker gain access
    to an otherwise restricted account by logging in
    using a variation on the account name.

  - A Renamed Account Remote Login Vulnerability
    The application continues to accept valid public keys
    for authentication to the Administrator or Guest
    accounts if either has been renamed or disabled after
    being configured for SSH public key authentication, 

  - An Information Disclosure Vulnerability
    Users with access to the remote host can read the server's
    private key, which can lead to host impersonation attacks." );
 script_set_attribute(attribute:"see_also", value:"http://support.wrq.com/techdocs/1867.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Reflection for Secure IT Server 6.0 build 24 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/25");
 script_cvs_date("$Date: 2016/06/13 20:14:28 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in AttachmateWRQ Reflection for Secure IT Server < 6.0 build 24";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}


port = get_kb_item("Services/ssh");
if (!port) port = 22;


banner = get_kb_item("SSH/banner/" + port);
if (banner) {
  if (egrep(string:banner, pattern:"WRQReflectionForSecureIT_([0-5]\.|6\.0 Build ([01]|2[0-3]))")) {
    security_warning(port);
    exit(0);
  }
}
