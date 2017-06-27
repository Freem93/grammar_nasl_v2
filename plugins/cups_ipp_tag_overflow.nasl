#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27608);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2014/05/25 02:11:20 $");

  script_cve_id("CVE-2007-4351");
  script_bugtraq_id(26268);
  script_osvdb_id(42028);

  script_name(english:"CUPS cups/ipp.c ippReadIO Function IPP Tag Handling Overflow");
  script_summary(english:"Checks CUPS server version");

  script_set_attribute(attribute:"synopsis", value:"The remote printer service is prone to a buffer overflow attack.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of CUPS installed on the remote
host fails to check the text-length field in the 'ippReadIO()'
function in 'cups/ipp.c'. Using a specially crafted request with an
IPP (Internet Printing Protocol) tag such as 'textWithLanguage' or
'nameWithLanguage' and an overly large text-length value, a remote
attacker may be able to leverage this issue to execute arbitrary code
on the affected system.");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2007-76/advisory/");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/483033/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L2561");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/articles.php?L508");
  script_set_attribute(attribute:"solution", value:"Upgrade to CUPS version 1.3.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:cups");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/cups", "Settings/ParanoidReport");
  script_require_ports("Services/www", 631);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


# nb: banner checks of open source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (!get_kb_item("www/cups")) exit(1, "The 'www/cups' KB item is missing.");

port = get_http_port(default:631, embedded: 1);


# Check the version in the banner.
banner = get_http_banner(port:port);
if (!banner) exit(1, "Failed to retrieve the banner from the web server on port "+ port +".");

banner = strstr(banner, "Server:");
banner = banner - strstr(banner, '\r\n');
if (!ereg(pattern:"^Server:.*CUPS($|/)", string:banner))
  exit(0, "The banner from port "+port+" is not from CUPS.");
if (!ereg(pattern:"CUPS/[0-9]", string:banner))
  exit(0, "The CUPS server on port "+port+" does not include its version in the banner.");

version = strstr(banner, "CUPS/") - "CUPS/";
if (" " >< version) version = version - strstr(version, " ");

if (version =~ "^1\.([0-2]|3\.[0-3])($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report = '\n' +
      'CUPS version ' + version + ' appears to be running on the remote host based\n' +
      'on the following Server response header :\n' +
      '\n'+
      '  ' + banner + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else if (version =~ "^(1|1\.3)($|[^0-9.])") exit(1, "The banner from the CUPS server listening on port "+port+" - "+banner+" - is not granular enough to make a determination.");
else exit(0, "CUPS version "+ version + " is listening on port "+port+" and thus not affected.");
