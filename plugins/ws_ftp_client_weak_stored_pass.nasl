#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14597);
 script_version("$Revision: 1.14 $");

 script_cve_id("CVE-1999-1078");
 script_bugtraq_id(547);
 script_osvdb_id(10356);

 script_name(english:"WS_FTP Pro Client Weak Password Encrypted");
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FTP client is using weak encryption."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of WS_FTP client installed on the remote host uses a weak
encryption method to store password information.  A local attacker
could exploit this to discover FTP passwords."
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to the latest version of WS_FTP client."
  );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/07/29");
 script_cvs_date("$Date: 2012/07/20 22:52:59 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:ipswitch:ws_ftp");
  script_end_attributes();

 script_summary(english:"Check IPSWITCH WS_FTP version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("ws_ftp_client_overflows.nasl");
 script_require_keys("ws_ftp_client/version");
 exit(0);
}

# start script

version = get_kb_item("ws_ftp_client/version");
if ( ! version ) exit(0);

if (ereg(string:version, pattern:"^([0-5]\.[0-9]\.[0-9]|6\.0\.0\.0[^0-9])")) 
  security_note(get_kb_item("SMB/transport")); 
