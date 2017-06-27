#
# (C) Tenable Network Security, Inc.
#

#
# This script checks for CVE-2002-1368, but incidentally covers
# all the issues listed, as they were all corrected in the
# same package
#

include("compat.inc");

if (description)
{
 script_id(11199);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2014/05/25 02:11:20 $");

 script_cve_id(
   "CVE-2002-1366",
   "CVE-2002-1367",
   "CVE-2002-1368",
   "CVE-2002-1369",
   "CVE-2002-1372",
   "CVE-2002-1383",
   "CVE-2002-1384"
 );
 script_bugtraq_id(6433, 6434, 6435, 6436, 6437, 6438, 6440, 6475);
 script_osvdb_id(10739, 10740, 10741, 10742, 10744, 10745, 10746, 10747);
 script_xref(name:"SuSE", value:"SUSE-SA:2003:002");

 script_name(english:"CUPS < 1.1.18 Multiple Vulnerabilities");
 script_summary(english:"Crashes the remote CUPS server");

 script_set_attribute(attribute:"synopsis", value:"The remote printer service has multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote CUPS server seems vulnerable to various flaws (buffer
overflow, denial of service, privilege escalation) that could allow a
remote attacker to shut down this service or remotely gain the
privileges of the 'lp' user.");
 script_set_attribute(attribute:"solution", value:"Upgrade to CUPS version 1.1.18 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/12/19");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/12/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/01/18");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:cups");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"Misc.");

 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_keys("www/cups", "Settings/ParanoidReport");
 script_require_ports("Services/www", 631);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);


function check(port)
{
 local_var banner, r, req;
 #
 # This attack is non-destructive.
 # A non-patched cups will reply nothing to :
 # POST /printers HTTP/1.1\r\nContent-length: -1\r\n\r\n" (and won't
 # crash until we add another \r\n at the end of the request),
 # whereas a patched cups will immediately reply with a code 400
 #

 if(http_is_dead(port:port))return(0);
 banner = get_http_banner(port:port);
 if(!banner)return(0); # we need to make sure this is CUPS

 if(egrep(pattern:"^Server: .*CUPS/.*", string:banner))
 {
 r = http_send_recv3(method:"POST", item: "/printers", port: port,
   add_headers: make_array("Authorization", "Basic AAA",
   		"Content-Length", "-1"));

 if (http_is_dead(port: port)) security_hole(port);	# The server dumbly waits for our data
 }
}

ports = add_port_in_list(list:get_kb_list("Services/www"), port:631);

foreach port (ports)
{
 check(port:port);
}
