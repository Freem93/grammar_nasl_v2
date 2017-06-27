#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62119);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/05/24 02:02:49 $");

  script_cve_id("CVE-2012-4244");
  script_bugtraq_id(55522);
  script_osvdb_id(85417);

  script_name(english:"ISC BIND Assertion Error Resource Record RDATA Query Parsing Remote DoS");
  script_summary(english:"Checks version of BIND");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server may be affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote installation
of BIND will exit with an assertion failure if a resource record with
RDATA in excess of 65535 bytes is loaded and then subsequently queried. 
 
Note that Nessus has only relied on the version itself and has not
attempted to determine whether or not the install is actually
affected.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-00778/74");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.6-ESV-R7-P3/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.7.6-P3/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.8.3-P3/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.9.1-P3/CHANGES");
  script_set_attribute(attribute:"solution", value:
"Upgrade to BIND 9.6-ESV-R7-P3 / 9.6-ESV-R8 / 9.7.6-P3 / 9.7.7 /
9.8.3-P3 / 9.8.4 / 9.9.1-P3 / 9.9.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/17");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = get_kb_item_or_exit("bind/version");

# Check whether BIND is vulnerable, and recommend an upgrade.
# Vuln 9.0.x < 9.6-ESV-R7-P3
fix = NULL;

if (ver =~ '^9\\.([0-5]($|[^0-9])|6(\\.|(-ESV($|-R([0-6]($|[^0-9])|7($|-P[0-2]($|[^0-9])))))))')
  fix = '9.6-ESV-R7-P3';
# Vuln 9.7.x < 9.7.6-P3
else if (ver =~ '^9\\.7\\.([0-5]($|[^0-9])|6($|-P[0-2]($|[^0-9])))')
  fix = '9.7.6-P3';
# Vuln 9.8.x < 9.8.3-P3
else if (ver =~ '^9\\.8\\.([0-2]($|[^0-9])|3($|-P[0-2]($|[^0-9])))')
  fix = '9.8.3-P3';
# Vuln 9.9.x < 9.9.1-P3
else if (ver =~ '^9\\.9\\.(0($|[^0-9])|1($|-P[0-2]($|[^0-9])))')
  fix = '9.9.1-P3';
else
  audit(AUDIT_LISTEN_NOT_VULN, "BIND", 53, ver, "UDP");

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_warning(port:53, proto:"udp", extra:report);
}
else security_warning(port:53, proto:"udp");
