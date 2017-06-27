#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

include("compat.inc");

if (description)
{
  script_id(16141);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/11/17 21:38:53 $");

  script_cve_id(
    "CVE-2004-1267",
    "CVE-2004-1268",
    "CVE-2004-1269",
    "CVE-2004-1270",
    "CVE-2005-2874"
  );
  script_bugtraq_id(11968, 12004, 12005, 12007, 12200, 14265);
  script_osvdb_id(12439, 12453, 12454, 12834);
  script_xref(name:"FLSA", value:"FEDORA-2004-559");
  script_xref(name:"FLSA", value:"FEDORA-2004-560");
  script_xref(name:"GLSA", value:"GLSA-200412-25");

  script_name(english:"CUPS < 1.1.23 Multiple Vulnerabilities");
  script_summary(english:"Checks version of CUPS");

  script_set_attribute(attribute:"synopsis", value:"The remote print service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of CUPS installed on the remote
host is between 1.0.4 and 1.1.22 inclusive. Such versions are prone to
multiple vulnerabilities :

  - A remotely exploitable buffer overflow in the 'hpgltops'
    filter that enable specially crafted HPGL files can
    execute arbitrary commands as the CUPS 'lp' account.

  - A local user may be able to prevent anyone from changing
    their password until a temporary copy of the new
    password
    file is cleaned up (lppasswd flaw).

  - A local user may be able to add arbitrary content to the
    password file by closing the stderr file descriptor
    while running lppasswd (lppasswd flaw).

  - A local attacker may be able to truncate the CUPS
    password file, thereby denying service to valid clients
    using digest authentication. (lppasswd flaw).

  - The application applies ACLs to incoming print jobs in a
    case-sensitive fashion. Thus, an attacker can bypass
    restrictions by changing the case in printer names when
    submitting jobs. [Fixed in 1.1.21.]");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L700");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L1024");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/str.php?L1023");
  script_set_attribute(attribute:"solution", value:"Upgrade to CUPS 1.1.23 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:cups");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 George A. Theall");
  script_family(english:"Misc.");

  script_dependencie("http_version.nasl");
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
if (version =~ "^1\.(0|1\.(1|2[0-2]))($|[^0-9])")
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
