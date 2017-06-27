#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14233);
  script_version("$Revision: 1.31 $");
  script_cvs_date("$Date: 2016/10/07 13:30:46 $");

  script_cve_id("CVE-2004-2057", "CVE-2004-2058", "CVE-2004-2059", "CVE-2004-2060");
  script_bugtraq_id(10799);
  script_osvdb_id(8251, 8252, 8253, 8254, 8255, 8256, 8257);

  script_name(english:"ASPrunner 2.4 Multiple Vulnerabilities");
  script_summary(english:"Check for multiple flaws in ASPrunner");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP script which is vulnerable to a
cross-site scripting issue.");
  script_set_attribute(attribute:"description", value:
"The remote host is running ASPrunner prior to version 2.5. There are
multiple flaws in this version of ASPrunner which would enable a
remote attacker to read and/or modify potentially confidential data.

An attacker, exploiting this flaw, would need access to the web server
via the network.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Jul/300");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencies("http_version.nasl", "no404.nasl", "cross_site_scripting.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (get_kb_item(strcat("www/", port, "/generic_xss"))) exit(0);

# there are multiple flaws.  We'll check for XSS flaw which will be an indicator
# of other flaws
#
# exploit string from http://www.securityfocus.com/bid/10799/exploit/
init = string("/export.asp?SQL=%22%3E%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3Eselect+%5Bword_id%5D%2C+%5Bword_id%5D%2C+++%5Btr%5D%2C+++%5Ben%5D%2C+++%5Bdesc%5D++From+%5Bdictionary%5D++order+by+%5Ben%5D+desc&mypage=1&pagesize=20");

r = http_send_recv3(port: port, item: init, method: 'GET');

if ("<script>alert" >< r[2])
{
  	security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}



