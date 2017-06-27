#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50976);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/04 14:21:29 $");

  script_cve_id("CVE-2010-3613", "CVE-2010-3614", "CVE-2010-3615");
  script_bugtraq_id(45133, 45134, 45137);
  script_osvdb_id(69558, 69559, 69568);
  script_xref(name:"CERT", value:"510208");
  script_xref(name:"CERT", value:"706148");
  script_xref(name:"CERT", value:"837744");

  script_name(english:"ISC BIND 9 9.4-ESV < 9.4-ESV-R4, 9.6.2 < 9.6.2-P3, 9.6-ESV < 9.6-ESV-R3, 9.7.x < 9.7.2-P3 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Bind9");

  script_set_attribute(attribute:"synopsis", value:"The remote name server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote installation
of BIND is affected by multiple vulnerabilities :

  - Failure to clear existing RRSIG records when a NO DATA
    is negatively cached could cause subsequent lookups to
    crash named. (CVE-2010-3613)

  - Named, when acting as a DNSSEC validating resolver,
    could incorrectly mark zone data as insecure when the
    zone being queried is undergoing a key algorithm
    rollover. (CVE-2010-3614)

  - Using 'allow-query' in the 'options' or 'view'
    statements to restrict access to authoritative zones has
    no effect. (CVE-2010-3615)");

  # ftp://ftp.isc.org/isc/bind9/9.4-ESV-R4/RELEASE-NOTES-BIND-9.4-ESV-R4.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ad86629");
  script_set_attribute(attribute:"see_also", value:"ftp://ftp.isc.org/isc/bind9/9.6.2-P3/RELEASE-NOTES-BIND-9.6.2-P3.html");
  # ftp://ftp.isc.org/isc/bind9/9.6-ESV-R3/RELEASE-NOTES-BIND-9.6-ESV-R3.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a364472f");
  script_set_attribute(attribute:"see_also", value:"ftp://ftp.isc.org/isc/bind9/9.7.2-P3/RELEASE-NOTES-BIND-9.7.2-P3.html");
  script_set_attribute(attribute:"see_also", value:"https://www.isc.org/software/bind/advisories/cve-2010-3613");
  script_set_attribute(attribute:"see_also", value:"https://www.isc.org/software/bind/advisories/cve-2010-3614");
  script_set_attribute(attribute:"see_also", value:"https://www.isc.org/software/bind/advisories/cve-2010-3615");
  script_set_attribute(attribute:"solution", value:"Upgrade to BIND 9.4-ESV-R4, 9.6.2-P3, 9.6-ESV-R3, 9.7.2-P3, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = get_kb_item_or_exit("bind/version");

if (
  version =~ '^9\\.[0-3]\\.' ||
  version =~ '^9\\.4-ESV($|-R[0-3]$)' ||
  version =~ '^9\\.5\\.' ||
  version =~ '^9\\.6\\.2($|-P[0-2]$)' ||
  version =~ '^9\\.6-ESV($|-R[0-2]$)' ||
  version =~ '^9\\.7\\.([01]($|[^0-9])|2([^0-9\\-]|$|-P[0-2]([^0-9]|$)))'
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 9.4-ESV-R4 / 9.6.2-P3 / 9.6-ESV-R3 / 9.7.2-P3\n';
    security_warning(port:53, proto:"udp", extra:report);
  }
  else security_warning(port:53, proto:"udp");
  exit(0);
}
else exit(0, 'Bind version ' + version + ' is running on port 53 and thus is not affected.');
