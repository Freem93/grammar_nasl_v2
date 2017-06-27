#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15417);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2014/10/06 13:11:38 $");

 script_cve_id("CVE-2004-0977");
 script_bugtraq_id(11295);
 script_osvdb_id(10941);

 script_name(english:"PostgreSQL make_oidjoins_check Arbitrary File Overwrite");
 script_summary(english:"Attempts to log into the remote PostgreSQL daemon");

 script_set_attribute(attribute:"synopsis", value:"The remote service is vulnerable to an unspecified flaw.");
 script_set_attribute(attribute:"description", value:
"The remote PostgreSQL server, according to its version number, is
vulnerable to an unspecified insecure temporary file creation flaw,
which may allow a local attacker to overwrite arbitrary files with the
privileges of the application.");
 script_set_attribute(attribute:"solution", value:"Upgrade to newer version of this software.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/18");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/04");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
 script_family(english:"Databases");

 script_dependencies("postgresql_detect.nasl");
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
     if(ereg(string:r, pattern:"PostgreSQL ([0-6]\.|7\.(4\.[0-5])|([0-3]\..*)).*")){
     	security_note(port);
	exit(0);
	}
     }
    exit(0);
   }
}
