#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22272);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2006-2113");
  script_bugtraq_id(19716);
  script_osvdb_id(28250);

  script_name(english:"Fuji Xerox Printing Systems (FXPS) Print Engine Crafted Request HTTP Authentication Bypass");
  script_summary(english:"Gets version of remote printer");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an authentication bypass isssue." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be a Fuji Xerox Printing Systems (FXPS)
printer. 

According to its firmware version, the web server component of the
FXPS device reportedly fails to authenticate HTTP requests, which could
allow a remote attacker to gain administrative control of the affected
printer and make unauthorized changes to it, including denying service
to legitimate users." );
 # http://web.archive.org/web/20060901153717/https://itso.iu.edu/20060824_FXPS_Print_Engine_Vulnerabilities
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f115f81" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/444321/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as referenced in the advisory." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/08/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/08/24");
 script_cvs_date("$Date: 2013/06/03 21:40:31 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);


# Make sure it's one of the affected printers.
w = http_send_recv3(method:"GET", item:"/ews/index.htm", port:port);
if (isnull(w)) exit(1, "the web server did not answer");
if ("Server: EWS-NIC" >!< w[1]) exit(0);


# Figure out the model.
model = NULL;
pat = "<title>([^<]+)</title";
matches = egrep(pattern:pat, string:w[2]);
if (matches) {
  foreach match (split(matches)) {
    match = chomp(match);
    model = eregmatch(pattern:pat, string:match);
    if (!isnull(model)) {
      model = model[1];
      break;
    }
  }
}
if (isnull(model)) exit(0);


# And its firmware version.
w = http_send_recv3(method:"GET", item:"/ews/status/infomation.htm", port:port);
if (isnull(w)) exit(1, "the web server did not answer");

ver = NULL;
pat = "Firmware Version<.+>([0-9]+)</td";
matches = egrep(pattern:pat, string:w[2]);
if (matches) {
  foreach match (split(matches)) {
    match = chomp(match);
    ver = eregmatch(pattern:pat, string:match);
    if (!isnull(ver)) {
      ver = ver[1];
      break;
    }
  }
}
if (isnull(ver)) exit(0);


# There's a problem if...
if (
  # it's a Dell Laser printer with an affected firmware version.
  "Dell Laser Printer" >< model &&
  (
    # nb: version numbers come from COMMENT_BUILD header in the patched prn files.
    ("5110cn" >< model && int(substr(ver, 0, 7)) < 20060601) ||
    ("3110cn" >< model && int(substr(ver, 0, 7)) < 20060526) ||
    ("3010cn" >< model && int(substr(ver, 0, 7)) < 20060602) ||
    ("5100cn" >< model && int(substr(ver, 0, 7)) < 20060607) ||
    ("3100cn" >< model && int(substr(ver, 0, 7)) < 20060607) ||
    ("3000cn" >< model && int(substr(ver, 0, 7)) < 20060607)
  )
) security_warning(port);
