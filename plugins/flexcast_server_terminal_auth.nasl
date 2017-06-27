#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18429);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2005-1897");
  script_bugtraq_id(13858);
  script_osvdb_id(17126);

  script_name(english:"FlexCast Server Terminal Authentication Unspecified Remote Issue");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a multimedia streaming application that is
affected by an authentication vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running FlexCast, an audio/video streaming server. 

According to its banner, the version installed on the remote host
suffers from a vulnerability in suppliers / terminal authentication. 
While details are as-yet unavailable, it is likely the flaw is
remotely exploitable." );
 # https://web.archive.org/web/20060702022820/http://archives.neohapsis.com/archives/apps/freshmeat/2005-05/0021.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e1b0316" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to FlexCast 2.0 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/06");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Checks for terminal authentication vulnerability in FlexCast Server");
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8000, 8001);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8000);


# Check the version number in the banner.
banner = get_http_banner(port:port);
if (
  banner && 
  banner =~ "^Server: FlexCast Server/[01]\."
) {
  security_hole(port);
}
