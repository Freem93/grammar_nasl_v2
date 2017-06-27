#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10181);
 script_version("$Revision: 1.27 $");
 script_cvs_date("$Date: 2016/05/16 14:22:06 $");

 script_cve_id("CVE-2000-0074");
 script_bugtraq_id(2653);
 script_osvdb_id(139);

 script_name(english:"PlusMail plusmail CGI Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/plusmail");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary files can be run on the remote host.");
 script_set_attribute(attribute:"description", value:
"The 'plusmail' CGI is installed. Some versions of this CGI have a well
known security flaw that lets an attacker read arbitrary file with the
privileges of the HTTP server.");
 script_set_attribute(attribute:"solution", value:"Remove it from /cgi-bin. No patch yet");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/01/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/01/12");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("webmirror.nasl", "http_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

res = is_cgi_installed3(item:"plusmail", port:port);
if(res)security_warning(port);
