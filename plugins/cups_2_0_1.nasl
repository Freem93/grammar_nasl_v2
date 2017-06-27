#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79580);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/24 13:12:21 $");

  script_cve_id("CVE-2014-3566");
  script_bugtraq_id(70574);
  script_osvdb_id(113251);
  script_xref(name:"CERT", value:"577193");

  script_name(english:"CUPS < 2.0.1 SSLv3 Legacy Encryption Vulnerability (POODLE)");
  script_summary(english:"Checks the CUPS server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote printer service is potentially affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the CUPS printer service installed on the
remote host is a version prior to 2.0.1. It is, therefore, potentially
affected by a man-in-the-middle (MitM) information disclosure
vulnerability known as POODLE. The vulnerability is due to the way SSL
3.0 handles padding bytes when decrypting messages encrypted using
block ciphers in cipher block chaining (CBC) mode. MitM attackers can
decrypt a selected byte of a cipher text in as few as 256 tries if
they are able to force a victim application to repeatedly send the
same data over newly created SSL 3.0 connections.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # Blog
  script_set_attribute(attribute:"see_also", value:"https://cups.org/blog.php?L734");
  # Bug
  script_set_attribute(attribute:"see_also", value:"https://cups.org/str.php?L4476");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Either upgrade to CUPS version 2.0.1 or later, or apply the vendor
patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:TF/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:cups");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cups_1_3_5.nasl");
  script_require_keys("www/cups", "Settings/ParanoidReport");
  script_require_ports("Services/www", 631);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:631, embedded:TRUE);
get_kb_item_or_exit("www/"+port+"/cups/running");

version = get_kb_item_or_exit("cups/"+port+"/version");
source  = get_kb_item_or_exit("cups/"+port+"/source");

if (version =~ "^(2|2\.0)($|[^0-9br.])") audit(AUDIT_VER_NOT_GRANULAR, "CUPS", port, version);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Affected :
# x.x.x < 2.0.1
if (
  version =~ "^1\." ||
  version =~ "^2\.0\.0($|[^0-9.])" ||
  version =~ "^2\.0(rc|b)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.0.1' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "CUPS", port, version);
