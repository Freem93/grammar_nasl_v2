#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59446);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/04 14:30:40 $");

  script_cve_id("CVE-2012-1667");
  script_bugtraq_id(53772);
  script_osvdb_id(82609);
  script_xref(name:"CERT", value:"381699");

  script_name(english:"ISC BIND 9 Zero-Length RDATA Section Denial of Service / Information Disclosure");
  script_summary(english:"Checks version of BIND.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server may be affected by a denial of service /
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote
installation of BIND does not properly handle resource records with a
zero-length RDATA section, which may lead to unexpected outcomes, such
as crashes of the affected server, disclosure of portions of memory,
corrupted zone data, or other problems. 

Note that Nessus has only relied on the version itself and has not
attempted to determine whether or not the install is actually
affected.");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.6-ESV-R7-P1/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.7.6-P1/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.8.3-P1/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.9.1-P1/CHANGES");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-00698");
  script_set_attribute(attribute:"see_also", value:"https://www.isc.org/software/bind/advisories/cve-2012-1667");

  script_set_attribute(attribute:"solution", value:
"Upgrade to BIND 9.6-ESV-R7-P1 / 9.7.6-P1 / 9.8.3-P1 / 9.9.1-P1 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/11");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = get_kb_item_or_exit("bind/version");
fix = NULL;

# Check whether BIND is vulnerable, and recommend an upgrade.
# Vuln 9.0.x < 9.6-ESV-R7-P1
if (ver =~ '^9\\.([0-5]($|[^0-9])|6(\\.|(-ESV($|-R([0-6]($|[^0-9])|7($|-P0))))))')
  fix = '9.6-ESV-R7-P1';
# Vuln 9.7.x < 9.7.6-P1
else if (ver =~ '^9\\.7\\.([0-5]($|[^0-9])|6($|-P0))')
  fix = '9.7.6-P1';
# Vuln 9.8.x < 9.8.3-P1
else if (ver =~ '^9\\.8\\.([0-2]($|[^0-9])|3($|-P0))')
  fix = '9.8.3-P1';
# Vuln 9.9.x < 9.9.1-P1
else if (ver =~ '^9\\.9\\.(0($|[^0-9])|1($|-P0))')
  fix = '9.9.1-P1';

if (!isnull(fix))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:53, proto:"udp", extra:report);
  }
  else security_hole(port:53, proto:"udp");
}
else audit(AUDIT_LISTEN_NOT_VULN, "BIND", 53, ver, "UDP");
