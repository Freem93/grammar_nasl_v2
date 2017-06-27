# - Written by Christoff Breytenbach <christoff@sensepost.com>
# - Checks only for passwords on Compaq Web-based / HP System Management
#   Agent on HTTPS (2381/tcp), and not on older versions with login
#   still on HTTP (2301/tcp)
# - Tested on CompaqHTTPServer 4.1, 4.2, 5.0, 5.7
#
# Changes by Tenable:
# - Revised plugin title, changed family (1/21/2009)

include("compat.inc");

if (description)
{
  script_id(11879);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2015/07/10 14:11:45 $");

  script_osvdb_id(3570);

  script_name(english:"Compaq Web-enabled Management Software Default Account");
  script_summary(english:"Detect Predictable Compaq Web-based Management / HP System Management Agent Administrator Passwords");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web-enabled management application that uses
default login credentials.");
  script_set_attribute(attribute:"description", value:
"The Compaq Web-based Management / HP System Management Agent active on
the remote host is configured with the default, or a predictable,
administrator password.  Depending on the agents integrated, this allows
an attacker to view sensitive and verbose system information, and may
even allow more active attacks such as rebooting the remote system. 
Furthermore, if an SNMP agent is configured on the remote host it may
disclose the SNMP community strings in use, allowing an attacker to set
device configuration if the 'write' community string is uncovered.");
  script_set_attribute(attribute:"solution", value:"Set a strong password for the administrator account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/10/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);

  script_copyright(english:"This script is Copyright (C) 2003-2015 SensePost");

  script_family(english:"Web Servers");

  script_dependencies("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 2381);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Check starts here

function https_get(port, request)
{
    local_var result, soc;

    if(get_port_state(port))
    {
         if(port == 2381)soc = open_sock_tcp(port, transport:ENCAPS_SSLv23);
	 else soc = open_sock_tcp(port);
         if(soc)
         {
            send(socket:soc, data:request);
            result = http_recv(socket:soc);
            close(soc);
            return(result);
         }
    }
}

debug = 0;

passlist = make_list ('administrator', 'admin', 'cim', 'cim7', 'password');

if ( thorough_tests )
 port = get_http_port(default:2381);
else
 port = 2381;

req = string("GET /cpqlogin.htm?RedirectUrl=/&RedirectQueryString= HTTP/1.0\r\n\r\n");

if(debug==1) display(req);

retval = https_get(port:port, request:req);
if(retval == NULL) exit(0);

if(debug == 1) display(retval);

if((retval =~ "HTTP/1.[01] 200") && ("Server: CompaqHTTPServer/" >< retval) && ("Cookie: Compaq" >< retval))
{
    foreach pass (passlist) {
        temp1 = strstr(retval, "Set-Cookie: ");
        temp2 = strstr(temp1, ";");
        cookie = temp1 - temp2;
	if ( ! cookie ) continue;
        cookie = str_replace(string:cookie, find:"Set-Cookie", replace:"Cookie");
        poststr = string("redirecturl=&redirectquerystring=&user=administrator&password=", pass);

        req = string("POST /proxy/ssllogin HTTP/1.0\r\n", cookie,
"\r\nContent-Length: ", strlen(poststr), "\r\n\r\n", poststr, "\r\n");

        if(debug==1) display("\n\n***********************\n\n", req);

        retval = https_get(port:port, request:req);

        if(debug==1) display(retval);

        if("CpqElm-Login: success" >< retval)
        {
            if (report_verbosity > 0)
            {
              report = '\n  User     : administrator' +
                       '\n  Password : ' + pass +
                       '\n';
              security_hole(port:port, extra:report);
            }
            else security_hole(port);
            exit(0);
        }
    }
}
audit(AUDIT_LISTEN_NOT_VULN, "Compaq Web-based Management / HP System Management Agent", port);
