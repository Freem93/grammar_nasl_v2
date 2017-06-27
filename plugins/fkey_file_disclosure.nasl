#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(16224);
 script_version ("$Revision: 1.12 $");
 script_bugtraq_id(12321);
 script_osvdb_id(13202);

 script_name(english:"FKey Arbitrary Remote File Disclosure");
 script_summary(english:"fkey file disclosure");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote finger daemon has an information disclosure vulnerability."
 );
 script_set_attribute(attribute:"description",  value:
"The remote finger daemon (possibly 'fkey') allows users to read
arbitrary files by supplying a file name that is 10 characters
or shorter.  A remote attacker could exploit this to read sensitive
information, which could be used to mount further attacks." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2005/Jan/229"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"There is no known fix at this time.  Disable this service."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/21");
 script_cvs_date("$Date: 2016/11/19 01:42:50 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");

 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc."); 

 script_dependencie("find_service1.nasl");
 script_require_ports("Services/finger", 79);

 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/finger");
if(!port)port = 79;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  buf = string("/etc/group\r\n");

  send(socket:soc, data:buf);
  data = recv(socket:soc, length:2048);
  close(soc);
  if ( egrep(pattern:"^bin:.:", string:data)  &&
       egrep(pattern:"^tty:.:", string:data)  &&
       egrep(pattern:"^nobody:.:", string:data)  )
	{
	report = "
Requesting the file /etc/group yielded : 

" + data +  "
";
	security_warning(port:port, extra:report);
 	}
   } 
}
