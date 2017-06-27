#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62355);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/12 14:36:12 $");

  script_cve_id("CVE-2012-1033");
  script_bugtraq_id(51898);
  script_osvdb_id(78916);
  script_xref(name:"CERT", value:"542123");

  script_name(english:"ISC BIND Cache Update Policy Deleted Domain Name Resolving Weakness");
  script_summary(english:"Checks version of BIND");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server may be affected by a DNS integrity
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote installation
of BIND will continue to allow revoked domain names to be resolved due
to an issue related to the cache update policy. 
 
Note that Nessus has only relied on the version itself and has not
attempted to determine whether or not the install is actually
affected.");
  # http://www.internetsociety.org/ghost-domain-names-revoked-yet-still-resolvable
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38f47769");
  script_set_attribute(attribute:"see_also", value:"https://www.isc.org/software/bind/advisories/cve-2012-1033");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.6-ESV-R6/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.7.5/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.8.2/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.9.0/CHANGES");
  script_set_attribute(attribute:"solution", value:"Upgrade to BIND 9.6-ESV-R6 / 9.7.5 / 9.8.2 / 9.9.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/27");

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
# Vuln 9.0.x < 9.6-ESV-R6
fix = NULL;

if (ver =~ '^9\\.([0-5]($|[^0-9])|6(\\.|(-ESV($|-R([0-5]($|[^0-9]))))))')
  fix = '9.6-ESV-R6';
# Vuln 9.7.x < 9.7.5
else if (ver =~ '^9\\.7\\.[0-4]($|[^0-9])')
  fix = '9.7.5';
# Vuln 9.8.x < 9.8.2
else if (ver =~ '^9\\.8\\.[0-1]($|[^0-9])')
  fix = '9.8.2';
# Vuln 9.9.x < 9.9.0
else if (ver =~ '^9\\.9\\.0([a-b][0-9]|rc[0-9])')
  fix = '9.9.0';
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
