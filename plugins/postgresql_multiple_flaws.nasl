#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11456);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2014/10/06 13:11:38 $");

 script_cve_id(
   "CVE-2002-1397",
   "CVE-2002-1398",
   "CVE-2002-1399",
   "CVE-2002-1400",
   "CVE-2002-1401",
   "CVE-2002-1402"
 );
 script_bugtraq_id(
   5497,
   5527,
   6610,
   6611,
   6612,
   6613,
   6614,
   6615,
   7075
 );
 script_osvdb_id(6190, 6191, 8998, 9504, 9505, 11829, 11830, 11831);
 script_xref(name:"RHSA", value:"2003:0010-10");

 script_name(english:"PostgreSQL < 7.2.3 Multiple Vulnerabilities");
 script_summary(english:"Attempts to log into the remote PostgreSQL daemon");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary commands may be run on the remote server.");
 script_set_attribute(attribute:"description", value:
"The remote PostgreSQL server, according to its version number, is
vulnerable to various flaws which may allow an attacker who has the
rights to query the remote database to obtain a shell on this host.");
 script_set_attribute(attribute:"solution", value:"Upgrade to postgresql 7.2.3 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/08/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/10/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/24");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
 script_family(english:"Databases");

 script_dependencie("postgresql_detect.nasl");
 script_require_ports("Services/postgresql", 5432);
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"postgresql", default:5432, exit_on_fail:TRUE);

#
# Request the database 'template1' as the user 'postgres' or 'pgsql'
#
zero = raw_string(0x00);

user[0] = "postgres";
user[1] = "pgsql";

for(i=0;i<2;i=i+1)
{
 soc = open_sock_tcp(port);
 if (!soc) audit(AUDIT_PORT_CLOSED, port);

 usr = user[i];
 len = 224 - strlen(usr);

 req = raw_string(0x00, 0x00, 0x01, 0x28, 0x00, 0x02,
    	         0x00, 0x00, 0x74, 0x65, 0x6D, 0x70, 0x6C, 0x61,
		 0x74, 0x65, 0x31) + crap(data:zero, length:55) +
        usr +
       crap(data:zero, length:len);

 send(socket:soc, data:req);
 r = recv(socket:soc, length:5);
 r2 = recv(socket:soc, length:1024);
 if((r[0]=="R") && (strlen(r2) == 10))
  {
    dbs = "";
    req = raw_string(0x51) + "select version();" +
    	  raw_string(0x00);
    send(socket:soc, data:req);

    r = recv(socket:soc, length:65535);
    r = strstr(r, "PostgreSQL");
    if(r != NULL)
     {
      for(i=0;i<strlen(r);i++)
      {
       if(ord(r[i]) == 0)
     	break;
       }
     r = substr(r, 0, i - 1);
     if(ereg(string:r, pattern:"PostgreSQL ([0-6]\.|7\.(2\.[0-2])|([0-1]\..*)).*")){
     	security_warning(port);
	}
     }
    else if("ERROR: function version()" >< r)security_warning(port);
    exit(0);
   }
}

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_PORT_CLOSED, port);

send(socket:soc, data:string("xx\r\n"));
r = recv(socket:soc, length:6);
close(soc);
if("EFATAL" >< r)
{
 if ( report_paranoia < 2 ) exit(0);
 security_warning(port:port, extra: "
Nessus was not able to remotely determine the version of the remote
PostgreSQL server, so this might be a false positive.
");
}
