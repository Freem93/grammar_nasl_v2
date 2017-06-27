#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15703);
 script_version ("$Revision: 1.15 $");

 script_cve_id("CVE-2004-2612");
 script_bugtraq_id(11650);
 script_osvdb_id(12144);
 
 script_name(english:"BNC IRC Server Incorrect Password Authentication Bypass");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote IRC proxy is susceptible to an authentication bypass issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the BNC IRC proxy that
contains a flaw in its authentication process that accepted only
logins with incorrect passwords.  An attacker may use this issue to
gain access to the remote IRC proxy server." );
 # http://web.archive.org/web/20041109090011/http://www.gotbnc.com/changes.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e9d3c1f" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BNC version 2.9.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/26");
 script_cvs_date("$Date: 2015/12/23 21:38:30 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Check BNC authentication bypass";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports(6667, 6669, 8080, "Services/irc-bnc");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

pwd = string("Nessus", rand());
nick = "nessus";
user = "nessus";


#most common bnc ports 6667,6669,8080

ports = make_service_list("Services/irc-bnc", 6667, 6669, 8080);

foreach port (ports)
{
   if(get_port_state(port))
   {

    soc = open_sock_tcp(port);
    if (soc)
    {

     req = 'user nessus nessus nessus nessus\nnick nessus ~\n';
     send(socket: soc, data: req);

     r = recv(socket:soc, length:4096);
     if (r)
     {

       if ("NOTICE AUTH :You need to say /quote PASS <password>" >!< r) exit(0);
       {
         req = string ('pass ', pwd, '\n');
         send (socket:soc, data:req);

         r = recv(socket:soc, length:4096);
         if ((r) && ("NOTICE AUTH :Welcome to BNC" >< r))
         { 
          security_hole(port);
          exit(0);
         }
       }
     }
   close (soc);
  }
 }
}
