#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56862);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/04 14:30:40 $");

  script_cve_id("CVE-2011-4313");
  script_bugtraq_id(50690);
  script_osvdb_id(77159);
  script_xref(name:"CERT", value:"606539");

  script_name(english:"ISC BIND 9 Query.c Logging Resolver Denial of Service");
  script_summary(english:"Checks version of BIND.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server may be affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote
installation of BIND is potentially affected by a denial of service
vulnerability.  An unidentified network event causes BIND9 resolvers
to cache an invalid record, subsequent queries for which could crash
the resolvers with an assertion failure. 

Note that Nessus has only relied on the version itself and has not
attempted to determine whether or not the install is actually
affected.");

  script_set_attribute(attribute:"see_also", value:"ftp://ftp.isc.org/isc/bind/9.4-ESV-R5-P1/CHANGES");
  script_set_attribute(attribute:"see_also", value:"ftp://ftp.isc.orc/isc/bind/9.6-ESV-R5-P1/CHANGES");
  script_set_attribute(attribute:"see_also", value:"ftp://ftp.isc.org/isc/bind/9.7.4-P1/CHANGES");
  script_set_attribute(attribute:"see_also", value:"ftp://ftp.isc.org/isc/bind/9.8.1-P1/CHANGES");
  script_set_attribute(attribute:"see_also", value:"https://www.isc.org/software/bind/advisories/cve-2011-4313");

  script_set_attribute(attribute:"solution", value:
"Upgrade to BIND 9.4-ESV-R5-P1 / 9.6-ESV-R5-P1 / 9.7.4-P1 / 9.8.1-P1
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/17");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2)
  exit(1, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

ver = get_kb_item_or_exit("bind/version");

# Check whether BIND is vulnerable, and recommend an upgrade.
if (ver =~ '^9\\.4-ESV([^\\-]|$|-R([0-4]([^0-9]|$)|5($|[^0-9\\-]|-P0($|[^0-9]))))')
  fix = '9.4-ESV-R5-P1';
else if (ver =~ '^9\\.6-ESV([^\\-]|$|-R([0-4]([^0-9]|$)|5($|[^0-9\\-]|-P0($|[^0-9]))))')
  fix = '9.6-ESV-R5-P1';
else if (ver =~ '^9\\.7\\.([0-3]($|[^0-9])|4($|[^\\-]|-P0($|[^0-9])))' || ver == '9.7.4b1' || ver == '9.7.4rc1')
  fix = '9.7.4-P1';
else if (ver =~ '^9\\.8\\.(0|1($|b[0-3]([^0-9]|$)|rc1([^0-9]|$)|[^\\-]|-P0([^0-9]|$)))')
  fix = '9.8.1-P1';
else 
  exit(0, "The BIND version " + ver + " server listening on UDP port 53 is not affected.");

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_hole(port:53, proto:"udp", extra:report);
} 
else security_hole(port:53, proto:"udp");
