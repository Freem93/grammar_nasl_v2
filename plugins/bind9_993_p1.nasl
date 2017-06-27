#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66838);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/23 20:31:31 $");

  script_cve_id("CVE-2013-3919");
  script_bugtraq_id(60338);
  script_osvdb_id(93913);

  script_name(english:"ISC BIND 9 Recursive Resolver Malformed Zone DoS");
  script_summary(english:"Checks version of BIND");

  script_set_attribute(attribute:"synopsis", value:"The remote name server is prone to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote installation
of BIND can be forced to crash via a 'RUNTIME_CHECK' error in
'resolver.c' caused by specially crafted queries for a record in a
malformed zone to a recursive resolver. 

Note that Nessus has only relied on the version itself and has not
attempted to determine whether or not the install is actually
affected.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-00967");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.6-ESV-R9-P1/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.8.5-P1/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.9.3-P1/CHANGES");
  script_set_attribute(attribute:"solution", value:
"Upgrade to BIND version 9.9.3-P1 / 9.8.5-P1 / 9.6-ESV-R9-P1 or later,
or apply the vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/07");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


ver = get_kb_item_or_exit("bind/version");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Check whether BIND is vulnerable, and recommend an upgrade.
# Vuln BIND 9.6-ESV-R9, 9.8.5, and 9.9.3 are affected
fix = NULL;

# Vuln 9.6-ESV-R9
if (ver =~ "^9\.6-ESV-R9(b[1-2]|rc[1-2])?$")
  fix = '9.6-ESV-R9-P1';
# Vuln 9.8.5
else if (ver =~ "^9\.8\.5(b[1-2]|rc[1-2])?$")
  fix = '9.8.5-P1';
# Vuln 9.9.3
else if (ver =~ "^9\.9\.3(b[1-2]|rc[1-2])?$")
  fix = '9.9.3-P1';
else
  audit(AUDIT_LISTEN_NOT_VULN, "BIND", 53, ver, "UDP");

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_hole(port:53, proto:"udp", extra:report);
}
else security_hole(port:53, proto:"udp");
