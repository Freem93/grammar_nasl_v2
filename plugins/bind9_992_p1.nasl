#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63166);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/05/24 02:02:49 $");

  script_cve_id("CVE-2012-5688");
  script_bugtraq_id(56817);
  script_osvdb_id(88126);

  script_name(english:"ISC BIND 9 DNS64 Handling DoS");
  script_summary(english:"Checks version of BIND");

  script_set_attribute(attribute:"synopsis", value:"The remote name server is prone to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote installation
of BIND can be forced to crash via maliciously crafted DNS requests. 

Note that this vulnerability only affects installs using the 'dns64'
configuration option. 
 
Further note that Nessus has only relied on the version itself and has
not attempted to determine whether or not the install is actually
affected.");
  script_set_attribute(attribute:"see_also", value:"http://www.isc.org/software/bind/advisories/cve-2012-5688");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-00828");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.8.4-P1/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.9.2-P1/CHANGES");
  script_set_attribute(attribute:"solution", value:
"Upgrade to BIND 9.8.4-P1 / 9.9.2-P1 or later.  Alternatively, disable
DNS64 functionality via configuration options.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/06");

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
# Vuln 9.8.0 < 9.8.4-P1 and 9.9.0 < 9.9.2-P1
fix = NULL;

# Vuln 9.8.0 < 9.8.4-P1
if (ver =~ "^9\.8\.([0-3]($|[^0-9])|4($|\.|a[1-9]|b[1-9]|rc[1-9]))")
  fix = '9.8.4-P1';
# Vuln 9.9.0 < 9.9.2-P1
else if (ver =~ "^9\.9\.([0-1]($|[^0-9])|2($|\.|a[1-9]|b[1-9]|rc[1-9]))")
  fix = '9.9.2-P1';
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
