#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55937);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/10/18 13:33:24 $");
  script_osvdb_id(77149);

  script_name(english:"Juniper Junos ICMP Ping 'composite next-hop' Remote DoS (PSN-2011-07-297)");
  script_summary(english:"Checks model & version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote router has a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the remote Juniper
router is running a version of Junos that is affected by a
denial of service vulnerability.  Sending an ICMP ping with
the record-route or timestamp options can crash an L3VPN PE
router with either of the following configurations :

  - Point-to-Multipoint LSPs that are used as next hops
    in configuration of static routes to customers' networks

  - The 'l3vpn-composite-nexthop' and 'indirect-next-hop'
    routing-options are enabled

A remote, unauthenticated attacker could exploit this to crash
the router."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22669bdd");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2011-07-297."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/22");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("misc_func.inc");
include("junos.inc");

fixes['9.3'] = '9.3S18';
fixes['10.0'] = '10.0S12';
fixes['10.2'] = '10.2R1';

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

check_model(model:model, flags:SRX_SERIES | MX_SERIES | J_SERIES | T_SERIES | M_SERIES, exit_on_fail:TRUE);
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_hole(port:0, extra:report);
}
else security_hole(0);

