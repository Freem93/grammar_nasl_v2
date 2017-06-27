#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description) {
 script_id(11895);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2002-0158", "CVE-2002-0164");
 script_bugtraq_id(4396, 4985);
 script_osvdb_id(8704, 14301, 86925);

 script_name(english:"SCO OpenServer Multiple Local Privilege Escalation Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by multiple local privilege escalation
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its telnet banner, the remote host is a SCO Unix server
running OpenServer version 5.0.5, 5.0.6, or 5.0.7.  Such versions are
vulnerable to two distinct exploits.  Namely,

  - Xsco can be locally exploited by any valid user in
    order to escalate their privileges to 'root'.  The bug 
    is due to improper input handling when running the 
    command line switch '-co'.

  - There is a vulnerability in the MIT-SHM extension within
    all X servers that are running as root.  Any user with 
    local X access can exploit the MIT-SHM extension and 
    gain read/write access to any shared memory segment on 
    the system." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=101776858410652&w=2" );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=103547625009363&w=2" );
 script_set_attribute(attribute:"see_also", value:"ftp://ftp.sco.com/pub/updates/OpenServer/CSSA-2003-SCO.26" );
 script_set_attribute(attribute:"solution", value:
"Install the patched binaries referenced in the vendor's advisory." );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/10/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/03/15");
 script_cvs_date("$Date: 2016/05/12 14:46:29 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_summary(english:"Checks the remote SCO OpenServer");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/telnet", 23);
 exit(0);
}




# start script

# kind of a hokey way to find the bug...but, both bugs are local...

include ("telnet_func.inc");

port = get_kb_item("Services/telnet");
if (!port) port=23;
r = get_telnet_banner(port:port); 
if (egrep(pattern:".*SCO OpenServer\(TM\) Release.*5\.0\.[5-7].*", string:r)) security_hole(0);
