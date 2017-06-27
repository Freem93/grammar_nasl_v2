#
# (C) Tenable Network Security, Inc.
#

# Reference:
# http://members.cox.net/ltlw0lf/printers.html
#

include("compat.inc");

if (description)
{
  script_id(10146);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2016/10/05 20:44:34 $");

  script_cve_id("CVE-1999-1508");
  script_bugtraq_id(806);
  script_osvdb_id(113);

  script_name(english:"Tektronix PhaserLink Printer Web Server Direct Request Administrator Access");
  script_summary(english:"Checks for the presence of /ncl_*.html");

  script_set_attribute(attribute:"synopsis", value:"The remote service is prone to unauthorized access.");
  script_set_attribute(attribute:"description", value:
"The file /ncl_items.html or /ncl_subjects.html exist on the remote
system. It is very likely that this file will allow an attacker to
reconfigure your Tektronix printer.

An attacker can use this to prevent the users of your network from
working properly by preventing themfrom printing their files.");
  # https://web.archive.org/web/20040319140242/http://archives.neohapsis.com/archives/bugtraq/2001-04/0482.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d7ca9505");
  script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to port 80 to this device, or disable the
Phaserlink web server on the printer (can be done by requesting
http://printername/ncl_items?SUBJECT=2097)");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"1999/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"1999/11/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencie("http_version.nasl");
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

i = "/ncl_items.html?SUBJECT=1";
if (is_cgi_installed3(item: i, port: port))
{
  if (!is_cgi_installed3(item: "/nessus" + rand() + ".html", port: port) )
  {
    security_warning(port);
    exit(0);
  }
}

if (is_cgi_installed3(item: "/ncl_subjects.html", port: port) )
{
    if (!is_cgi_installed3(item: "/nessus" + rand() + ".html", port: port) ) security_warning(port);
}
