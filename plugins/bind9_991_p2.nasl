#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60120);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/23 20:31:31 $");

  script_cve_id("CVE-2012-3817", "CVE-2012-3868");
  script_bugtraq_id(54658, 54659);
  script_osvdb_id(84228, 84229);

  script_name(english:"ISC BIND 9 Multiple Denial of Service Vulnerabilities");
  script_summary(english:"Checks version of BIND.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server may be affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote
installation of BIND is affected by multiple denial of service
vulnerabilities :

  - Under a heavy query load, the application may use
    uninitialized data structures related to failed query
    cache access. This error can cause the application to
    crash. Note this issue only affects the application
    when DNSSEC validation is enabled. (CVE-2012-3817)

  - Under a heavy, incoming TCP query load, the application
    can be affected by a memory leak that can lead to
    decreased performance and application termination on
    systems that kill processes that are out of memory.
    (CVE-2012-3868)

Note that Nessus has only relied on the version itself and has not
attempted to determine whether or not the install is actually
affected.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-00729");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-00730");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.6-ESV-R7-P2/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.7.6-P2/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.8.3-P2/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.9.1-P2/CHANGES");

  script_set_attribute(attribute:"solution", value:
"Upgrade to BIND 9.6-ESV-R7-P2 / 9.7.6-P2 / 9.8.3-P2 / 9.9.1-P2 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/25");

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

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = get_kb_item_or_exit("bind/version");
fix = NULL;

# Check whether BIND is vulnerable, and recommend an upgrade.
# Vuln 9.0.x < 9.6-ESV-R7-P2
if (ver =~ '^9\\.([0-5]($|[^0-9])|6(\\.|(-ESV($|-R([0-6]($|[^0-9])|7($|-P[01]($|[^0-9])))))))')
  fix = '9.6-ESV-R7-P2';
# Vuln 9.7.x < 9.7.6-P2
else if (ver =~ '^9\\.7\\.([0-5]($|[^0-9])|6($|-P[01]($|[^0-9])))')
  fix = '9.7.6-P2';
# Vuln 9.8.x < 9.8.3-P2
else if (ver =~ '^9\\.8\\.([0-2]($|[^0-9])|3($|-P[01]($|[^0-9])))')
  fix = '9.8.3-P2';
# Vuln 9.9.x < 9.9.1-P2
else if (ver =~ '^9\\.9\\.(0($|[^0-9])|1($|-P[01]($|[^0-9])))')
  fix = '9.9.1-P2';

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
