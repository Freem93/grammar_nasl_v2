#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55533);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/04 14:30:40 $");

  script_cve_id("CVE-2011-2465");
  script_bugtraq_id(48565);
  script_osvdb_id(73604);
  script_xref(name:"CERT", value:"137968");
  script_xref(name:"Secunia", value:"45185");

  script_name(english:"ISC BIND Response Policy Zones (RPZ) DNAME / CNAME Parsing Remote DoS");
  script_summary(english:"Checks version of BIND.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server may be affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote
installation of BIND is potentially affected by a denial of service
vulnerability.  If an attacker sends a specially crafted request to a
BIND server that has recursion enabled and Response Policy Zones (RPZ)
configured, it may cause the name server process to crash. 

Note that Nessus has only relied on the version itself and has not
attempted to determine whether or not the install is actually
affected.");
  script_set_attribute(attribute:"see_also", value:"http://www.isc.org/software/bind/advisories/cve-2011-2465");

  script_set_attribute(attribute:"solution", value:
"Upgrade to BIND 9.8.0-P3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/07");
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

# Check whether BIND is vulnerable.
if (ver !~ "^9\.8\.0($|-P[12]($|[^0-9]))" && ver != "9.8.1b1")
  exit(0, "BIND version " + ver + " is running on UDP port 53 and thus is not affected.");

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : 9.8.0-P3' +
    '\n';
  security_hole(port:53, proto:"udp", extra:report);
} else security_hole(port:53, proto:"udp");
