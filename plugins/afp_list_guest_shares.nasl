#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(45380);
  script_version ("$Revision: 1.3 $");

  script_name(english:"AFP Server Share Enumeration (guest)");
  script_summary(english:"Displays the list of AFP shares");

  script_set_attribute(
    attribute:'synopsis',
    value:'The "guest" user can access some network shares.'
  );
  script_set_attribute(
    attribute:'description',
    value:
"The remote AFP server allows guest users to connect to several
shares. 

Make sure this is in line with your organization's security policy."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"If you do not want the 'guest' user to be able to access any share on
the remote system :

  - On Mac OS X client, edit System Preferences -> Accounts 
    -> Guest and uncheck the option 'Allow guests to connect
    to shared folders'.

  - On Mac OS X server, edit the AFP service and disable 
    option 'Allow guests to connect'."
  );
  script_set_attribute(attribute:'risk_factor', value:'None');
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/30");
 script_cvs_date("$Date: 2011/03/11 21:52:30 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_family(english:"Misc.");
  script_dependencies("asip-status.nasl");
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
report = NULL;

if ( DSI_LastError() == 0 && max_index(shares) > 0 )
{
 report = '\nThe following shares can be read as \'guest\' :\n\n';
 for ( n = 0 ; n < max_index(shares) ; n ++ )
 {
  report += '- ' + shares[n] + '\n';
  ret = FPOpenVol(shares[n]);
  if ( DSI_LastError() == 0 )
  {
   volume_id = FPOpenVolParseReply(ret);
   x = FPEnumerateExt2(volume_id:volume_id, DID:2, path:"");
   if ( DSI_LastError() == 0 )
   {
    data = FPEnumerateExt2Parse(x);
    if ( max_index(data) > 0 )
    {
     report += 'Contents : \n';
     for ( i = 0 ; i < max_index(data); i ++ )
	report += '  - ' + data[i] + '\n';
     report += '\n';
     }
    }
    FPCloseVol(volume_id);
   }
 }
}

FPLogout();
CloseSession();

if ( strlen(report) > 0 ) security_note(port:port, extra:report);
