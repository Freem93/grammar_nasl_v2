#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40418);
  script_version("$Revision: 1.10 $");

  script_bugtraq_id(35783);
  script_osvdb_id(56540);
  script_xref(name:"Secunia", value:"35969");

  script_name(english:"CommuniGate Pro WebMail < 5.2.15 XSS");
  script_summary(english:"Checks for CommuniGate Pro < 5.2.15");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting
vulnerability." );

  script_set_attribute(attribute:"description", value:
"According to its banner, the remote web server is from a version of
CommuniGate Pro older than 5.2.15.  The webmail component of such
versions fails to correctly parse plaintext email messages containing
malicious URL links before displaying the message to the user.  By
sending a specially crafted email message to the victim's email
address, an attacker may be able to leverage this issue to execute
arbitrary JavaScript code within the user's browser session every time
the email message is read." );

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ba42c1d" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2009/Jul/173" );
  script_set_attribute(attribute:"see_also", value:"http://www.communigate.com/cgatepro/History52.html" );

  script_set_attribute(attribute:"solution", value:
"Upgrade to CommuniGate Pro 5.2.15 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date",   value:"2009/07/23");
  script_set_attribute(attribute:"patch_publication_date",  value:"2009/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/29");
  
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:communigate:communigate_pro_core_server");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www",8100);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8100);

# Check the version in the banner.
banner = get_http_banner(port:port);

if (! banner) exit(1, "No HTTP banner on port "+port);
if ("CommuniGatePro" >!< banner)
  exit(0, "CommuniGatePro is not running on port "+port);

if (egrep(pattern:"^Server: CommuniGatePro/([0-4]\.|5\.([0-1][^0-9])|5\.2\.([0-9]|1[0-4])($|[^0-9]))", string:banner)) 
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  if (report_verbosity > 0)
  {
    serv = strstr(banner, "Server:");
    serv = serv - strstr(serv, '\r\n');

    report = string('\n',
                     'The remote CommuniGatePro server responded with the following banner :','\n\n',
                     serv,'\n');
     security_warning(port:port,extra:report);
  } 
  else security_warning(port);
}
else exit(0, "The installed version of CommuniGate Pro is not affected.");

