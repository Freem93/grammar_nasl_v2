#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20805);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2005-3653");
  script_bugtraq_id(16354);
  script_osvdb_id(22688);
  script_xref(name:"IAVA", value:"2006-A-0008");
 
  script_name(english:"CA iTechnology iGateway Service Content-Length Buffer Overflow");
  script_summary(english:"Checks for Content-Length buffer overflow vulnerability in iTechnology iGateway");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is using CA iTechnology iGateway service, a 
software component used in various products from CA.

The version of the iGateway service installed on the remote host
reportedly fails to sanitize Content-Length HTTP header values before
using them to allocate heap memory.  An attacker can supply a negative
value, which causes the software to allocate a small buffer, and then
overflow that with a long URI.  Successful exploitation of this issue
can lead to a server crash or possibly the execution of arbitrary
code.  Note that, under Windows, the server runs with local SYSTEM
privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?059ed5ba" );
 script_set_attribute(attribute:"see_also", value:"http://supportconnectw.ca.com/public/ca_common_docs/igatewaysecurity_notice.asp" );
 script_set_attribute(attribute:"solution", value:
"Contact the vendor to upgrade to iGateway 4.0.051230 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/01/23");
 script_cvs_date("$Date: 2013/06/03 16:47:46 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/01/23");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"stig_severity", value:"I");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 5250);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:5250);

# Get a list of all sponsors.
w = http_send_recv3(method:"GET", item:"/igsponsor", port:port);
if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");

# If it looks like iGateway...
#
# nb: iGateway doesn't seem to include a server response header
#     there's a valid request.
if ("Server: iGateway" >< w[1])
{
  res = strcat(w[0], w[1], '\r\n', w[2]);
  # Pull out the version number components.
  sponsor = strstr(res, "<SponsorName>iControl");
  if (sponsor) {
    ver_maj = strstr(sponsor, "<MajorVersion>");
    if (ver_maj) {
      ver_maj = ver_maj - strstr(ver_maj, "</");
      ver_maj = strstr(ver_maj, ">");
      ver_maj = ver_maj - ">";
    }
    ver_min = strstr(sponsor, "<MinorVersion>");
    if (ver_min) {
      ver_min = ver_min - strstr(ver_min, "</");
      ver_min = strstr(ver_min, ">");
      ver_min = ver_min - ">";
    }
    ver_svc = strstr(sponsor, "<ServicePackVersion>");
    if (ver_svc) {
      ver_svc = ver_svc - strstr(ver_svc, "</");
      ver_svc = strstr(ver_svc, ">");
      ver_svc = ver_svc - ">";
    }
    # Check the version number.
    if (!isnull(ver_maj) && !isnull(ver_min) && !isnull(ver_svc)) {
      iver_maj = int(ver_maj);
      iver_min = int(ver_min);
      iver_svc = int(ver_svc);

      # There's a problem if the version is < 4.0.051230
      #
      # nb: ver_svc is in the form YYMMDD.
      if (
        iver_maj < 4 ||
        (iver_maj == 4 && iver_min == 0 && iver_svc < 51230)
      ) {
        security_hole(port);
      }
    }
  }
}
