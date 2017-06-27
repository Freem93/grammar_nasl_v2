#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14771);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");

 script_bugtraq_id(13777, 13778);
 script_osvdb_id(10068);

 script_name(english:"Apache <= 1.3.33 htpasswd Local Overflow");
 script_summary(english:"Checks for Apache <= 1.3.33");

 script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by a buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Apache 1.3.33 or older.

There is a local buffer overflow in the 'htpasswd' command in these
versions that may allow a local user to gain elevated privileges if
'htpasswd' is run setuid or a remote user to run arbitrary commands
remotely if the script is accessible through a CGI.

*** Note that Nessus solely relied on the version number *** of the
remote server to issue this warning. This might *** be a false
positive");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Oct/356");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2004/Sep/565" );
 script_set_attribute(attribute:"solution", value:
"Make sure htpasswd does not run setuid and is not accessible through
any CGI scripts.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/16");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/17");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

 script_family(english:"Web Servers");

 script_dependencie("http_version.nasl", "macosx_version.nasl");
 script_require_keys("www/apache", "Settings/ParanoidReport");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("audit.inc");
include("backport.inc");
include('global_settings.inc');
include("http_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

if(get_port_state(port))
{
banner = get_http_banner(port: port);
if(!banner)exit(0);
banner = get_backport_banner(banner:banner);

serv = strstr(banner, "Server:");
if(!serv)exit(0);

if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/(1\.([0-2]\.[0-9]|3\.([0-9][^0-9]|[0-1][0-9]|2[0-9]|3[0-3])))", string:serv))
 {
   security_warning(port);
 }
}
