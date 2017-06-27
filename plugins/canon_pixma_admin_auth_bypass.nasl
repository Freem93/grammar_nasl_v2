#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(73375);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/04/07 15:56:14 $");

  script_cve_id("CVE-2013-4613");
  script_bugtraq_id(60612);
  script_osvdb_id(94418);

  script_name(english:"Canon PIXMA Printer Administration Authentication Bypass");
  script_summary(english:"Attempts to obtain access web administration of printer");

  script_set_attribute(attribute:"synopsis", value:"The remote printer is affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote printer contains a flaw that could allow a remote attacker
to obtain sensitive information. The HTTP admin interface does not
require credentials.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Jun/145");
  script_set_attribute(attribute:"see_also", value:"http://www.mattandreko.com/2013/06/canon-y-u-no-security.html");
  script_set_attribute(attribute:"solution", value:"Set an administrative password on the device.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:canon:pixma_printer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("canon_pixma_printer_www_detect.nbin");
  script_require_ports("Services/www", 80);
  script_require_keys("www/canon_pixma");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("network_func.inc");

# May fork
port = get_kb_item_or_exit("www/canon_pixma");

# Make the request and check for disclosure
res = http_send_recv3(
  method : "GET",
  item   : "/English/pages_WinUS/top_content.html",
  port   : port
);

url = "/English/pages_MacUS/top_content.html";

if (!res)
{
  res = http_send_recv3(
    method       : "GET",
    item         : url,
    port         : port,
    exit_on_fail : TRUE
  );
}

if (
 "series Network Configuration</title>" >< res[2] &&
 "Firmware Version:</th>" >< res[2] &&
 '<font color="white"><b>Printer Information</b></font>' >< res[2]
)
{
  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able access the following URL : '+
      '\n  URL        : ' + build_url(qs:url, port:port) +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The remote Canon PIXMA printer listening on port " + port + " is not affected.");
