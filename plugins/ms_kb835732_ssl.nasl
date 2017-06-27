#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12204);
 script_version("$Revision: 1.29 $");
 script_cve_id("CVE-2004-0120");
 script_bugtraq_id(10115);
 script_osvdb_id(5260);
 script_xref(name:"MSFT", value:"MS04-011");

 script_name(english:"MS04-011: Microsoft Windows SSL Library Malformed Message Remote DoS (835732) (uncredentialed check)");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running a version of Microsoft SSL library
which is vulnerable to several flaws, ranging from a denial of service
to remote code executing.

Any Microsoft service that utilizes SSL is vulnerable.  This
includes IIS 4.0, IIS 5.0, IIS 5.1, Exchange Server 5.5, Exchange Server
2000, Exchange Server 2003, and Analysis Services 2000 (included with
SQL Server 2000)." );
 script_set_attribute(attribute:"solution", value:
"Install the Windows cumulative update from Microsoft." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms04-011" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/04/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/04/14");
 script_cvs_date("$Date: 2016/11/28 21:52:57 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_summary(english:"Checks for Microsoft Hotfix KB835732 by talking to the remote SSL service");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencie("find_service1.nasl");
 script_require_ports("Transport/SSL", 443, 636);
 exit(0);
}

# start script

include("misc_func.inc");
ports = get_kb_list("Transport/SSL");
if ( isnull(ports) ) ports = make_list(443, 636);
else { 
       ports = add_port_in_list(list:make_list(ports), port:443);
       ports = add_port_in_list(list:ports, port:636);
}




req = raw_string(0xFF, 0xFF, 0xFF, 0xFF) + string("NESSUS");                          # Identifier
req = req + raw_string(0xFF, 0x37, 0x57, 0x73, 0x35, 0x33, 0xE6, 0x80, 0x33, 0x42);   # continuation data
req = req + crap(data:raw_string(0xFF), length:70);                             # these bytes don't matter 

foreach port (ports) {
    if(get_port_state(port)) {
        soc=open_sock_tcp(port, transport:ENCAPS_IP);
        if (soc) { 
            send(socket:soc, data:req);

            for (i=0; i<4; i++) {
                r = recv(socket:soc, length:7, timeout:1);
                if (r) break;
            }
            close(soc);

            # so, pre-patch, IIS will send back 
            # 80 05 05 00 03 00 00
            #
            # post-patch, IIS just FINs the connection


            if (r) {
                if (strlen(r) == 7) { 
                    if ( (ord(r[0]) == 0x80) && (ord(r[1]) == 0x05) && (ord(r[2]) == 0x05) ) security_hole(port);
                }
            }
        }
    }
}




