#
# (C) Tenable Network Security, Inc.
#

# References:
#
# http://www.nessus.org/u?fd6d1531
#
# Date:  Sun, 10 Mar 2002 21:37:33 +0100
# From: "Obscure" <obscure@eyeonsecurity.net>
# To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: IMail Account hijack through the Web Interface
#
#  Date:  Mon, 11 Mar 2002 04:11:43 +0000 (GMT)
# From: "Zillion" <zillion@safemode.org>
# To: "Obscure" <obscure@zero6.net>
# CC: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org, "Obscure" <obscure@eyeonsecurity.net>
# Subject: Re: IMail Account hijack through the Web Interface
#



include("compat.inc");

if(description)
{
 script_id(11271);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2001-1286");
 script_bugtraq_id(3432);
 script_osvdb_id(10845);
 
 script_name(english:"Ipswitch IMail Web Interface URI Referer Session Token Disclosure");
 script_summary(english:"Checks for version of IMail web interface");

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by an information disclosure 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running IMail web interface. In this version, the
session is maintained via the URL. It will be disclosed in the 
Referer field if you receive an email with external links (e.g. images)" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Oct/82" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Mar/164" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Mar/165" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Mar/206" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Mar/221" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IMail 7.06  or turn off the 'ignore source address 
in security check' option." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/02/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/10/11");
 script_cvs_date("$Date: 2016/10/27 15:03:54 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:ipswitch:imail"); 
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
 #script_require_keys("www/IMail");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

banner = get_http_banner(port: port);
if (isnull(banner)) exit(1, "Failed to get the banner from port "+port+".");

serv = egrep(string: banner, pattern: "^Server:.*");
if(serv && ereg(pattern:"^Server:.*Ipswitch-IMail/(([1-6]\.)|(7\.0[0-5]))", string:serv))
   security_warning(port);
