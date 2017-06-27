#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(47716);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id("CVE-2010-1748");
  script_bugtraq_id(40897);
  script_osvdb_id(65569);
  script_xref(name:"Secunia", value:"40165");

  script_name(english:"CUPS Memory Information Disclosure");
  script_summary(english:"Checks for memory information disclosure in CUPS web interface");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote CUPS install contains a memory information disclosure
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote CUPS install contains a memory information disclosure
vulnerability due to an error in 'cgi_initialize_string' in
'cgi-bin/var.c', which mishandles input parameters containing the '%'
character."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/apple/cups/issues/3577"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to CUPS 1.4.4 or greater."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/06/15");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/14");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:cups");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
  
  script_dependencies("cups_1_3_5.nasl");
  script_require_ports("Services/www", 631);
  script_require_keys("www/cups");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:631, embedded:TRUE);
if (!get_kb_item("www/"+port+"/cups/running"))
  exit(0, "The web server on port "+port+" is not running CUPS.");

exploit = '/admin?OP=redirect&URL=%';
w = http_send_recv3(
  method          : "GET",
  item            : exploit,
  port            : port,
  follow_redirect : 0,
  exit_on_fail    : TRUE
);

if (egrep(pattern:"^Location:.*\%FF.*/cups/cgi-bin/admin\.cgi", string:w[1]))
{
  if (report_verbosity > 0)
  {
    report = '\n' +
       'Nessus was able to verify the vulnerability using the following URL :\n' +
       '\n' +
       build_url(port:port, qs:exploit) + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, 'The CUPS server on port ' + port + ' is not affected.');
