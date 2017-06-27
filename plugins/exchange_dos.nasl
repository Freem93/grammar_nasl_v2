#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(10558);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2013/11/04 02:28:17 $");

 script_cve_id("CVE-2000-1006");
 script_bugtraq_id(1869);
 script_osvdb_id(457);
 script_xref(name:"MSFT", value:"MS00-082");

 script_name(english:"Exchange Malformed MIME Header Handling DoS");
 script_summary(english:"Checks the remote banner");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote SMTP server has a denial of service vulnerability."
 );
 script_set_attribute( attribute:"description",
   value:
"The remote Exchange server seems to be vulnerable to a flaw that lets
malformed MIME headers crash it. 

*** Nessus did not actually test for these flaws - it just relied
*** on the banner to identify them. Therefore, this warning may be
*** a false positive - especially since the banner DOES NOT CHANGE
*** if the patch has been applied." );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms00-082");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Exchange 5.0 and 5.5.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/10/31");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/11/27");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"SMTP problems");

 script_copyright(english:"This script is Copyright (C) 2000-2013 Tenable Network Security, Inc.");

 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl");
 script_require_ports("Services/smtp", 25);

 exit(0);
}

#

include("misc_func.inc");
include("smtp_func.inc");

port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

 banner = get_smtp_banner(port:port);
 if(!banner)exit(0);
 if(ereg(string:banner,
	   pattern:".*Microsoft Exchange Internet Mail Service 5\.5\.((1[0-9]{0,3})|(2(([0-5][0-9]{2})|(6(([0-4][0-9])|(50\.(([0-1][0-9])|(2[0-1])))))))).*"))
		security_warning(port);


