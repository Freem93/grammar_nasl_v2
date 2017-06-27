#
# (C) Tenable Network Security, Inc.
#

# Reference:
# http://members.cox.net/ltlw0lf/printers.html
#

include("compat.inc");

if (description)
{
  script_id(10665);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2016/10/27 15:03:55 $");

  script_cve_id("CVE-2001-0484");
  script_bugtraq_id(2659);
  script_osvdb_id(551);

  script_name(english:"Tektronix PhaserLink Multiple Admin Page Unauthenticated Configuration Manipulation");
  script_summary(english:"Checks for the presence of _ncl_*.shtml");

  script_set_attribute(attribute:"synopsis", value:"The remote service is prone to unauthorized access.");
  script_set_attribute(attribute:"description", value:
"The file /_ncl_items.shtml or /_ncl_subjects.shtml exists on the
remote web server. If the remote host is a Tektronix printer, then
this page allows anyone to reconfigure it without any authentication
means whatsoever.

An attacker may use this flaw to conduct a denial of service attack
against your business by preventing legitimate users from printing
their work, or against your network, by changing the IP address of the
printer so that it conflicts with the IP address of your file server.");
  # https://web.archive.org/web/20020222032650/http://archives.neohapsis.com/archives/bugtraq/2001-04/0482.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c775ca26");
  script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to port 80 to this device, contact Tektronix
for a patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"1999/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/05/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencie("http_version.nasl", "no404.nasl");
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

i = "/_ncl_items.shtml?SUBJECT=1";
if (is_cgi_installed3(port: port, item: i))
{
  if ( ! is_cgi_installed3(port: port, item: "/nessus"+rand()+".shtml?SUBJECT=1") )
  {
    security_warning(port);
    exit(0);
  }
}

if (is_cgi_installed3(port: port, item: "/_ncl_subjects.shtml"))
{
	if ( ! is_cgi_installed3(port: port, item: "/nessus"+rand()+".shtml?SUBJECT=1") ) security_warning(port);
}
