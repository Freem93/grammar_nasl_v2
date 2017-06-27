#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11464);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2014/05/25 01:17:39 $");

 script_cve_id("CVE-2001-0025");
 script_bugtraq_id(2103);
 script_osvdb_id(13123);

 script_name(english:"Leif Wright ad.cgi file Parameter Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/ad.cgi");
 script_set_attribute(attribute:"synopsis", value:"Arbitrary commands can be run on the remote server.");
 script_set_attribute(attribute:"description", value:
"The CGI 'ad.cgi' is installed. This CGI has a well known security flaw
that lets an attacker execute arbitrary commands with the privileges
of the http daemon (usually root or nobody).");
 script_set_attribute(attribute:"solution", value:"Remove it from /cgi-bin.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/12/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/25");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 res = is_cgi_installed3(item: strcat(dir, "/ad.cgi"), port:port);
 if(isnull(res)) exit (0);
 if(res) { security_hole(port); exit(0); }
}
