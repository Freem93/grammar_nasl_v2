#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(45374);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/09/24 20:59:27 $");

  script_cve_id("CVE-2010-0533");
  script_bugtraq_id(39020);
  script_osvdb_id(63366);

  script_name(english:"AFP Server Directory Traversal");
  script_summary(english:"Checks for the AFP .. attack");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to an information 
disclosure attack.'
  );
  script_set_attribute(
    attribute:'description',
    value:
"The remote AFP server allows guest users to read files
located outside public shares by sending requests to the '..'
directory. 

An attacker could use this flaw to read every file on this host."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT4077"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2010/Mar/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/advisories/19364"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Mac OS X 10.6.3 or apply Security Update 2010-002."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_family(english:"Misc.");
  script_dependencies("asip-status.nasl", "os_fingerprint.nasl");
  script_require_keys("AFP/GuestAllowed");
  script_require_ports("Services/appleshare");
  exit(0);
}


include("byte_func.inc");
include("afp_func.inc");
include("misc_func.inc");

port = get_service(svc:"appleshare", default:548, exit_on_fail:TRUE);

soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open socket on port "+port+".");

OpenSession(soc);
if ( DSI_LastError() != 0 ) exit(0, "Could not open a session.");

FPLogin();
if ( DSI_LastError() != 0 ) exit(0, "Could not log into the remote host.");

ret = FPGetSrvrParms();
if ( DSI_LastError() != 0 ) exit(0, "Could not get the server parameters.");

shares = FPGetSrvrParmsParseReply(ret);
if ( DSI_LastError() == 0 )
{
 for ( n = 0 ; n < max_index(shares) ; n ++ )
 {
  ret = FPOpenVol(shares[n]);
  if ( DSI_LastError() == 0 ) break;
 }
 if ( DSI_LastError() == 0 )
 {
  volume_id = FPOpenVolParseReply(ret);
 
  x = FPEnumerateExt2(volume_id:volume_id, DID:2, path:"..");
  if ( DSI_LastError() == 0 )
  {
   data = FPEnumerateExt2Parse(x);
   report = '\nIt was possible to obtain a listing of \'..\' for the share \'' + shares[n] + '\' :\n';
  for ( i = 0 ; i < max_index(data) ; i ++ )
   report += ' - ' + data[i] + '\n';
 
  security_warning(port:port, extra:report);
  }
  FPCloseVol(volume_id);
 }
}

FPLogout();
CloseSession();
