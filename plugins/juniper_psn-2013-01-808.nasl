#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63520);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/10/18 13:33:25 $");

  script_osvdb_id(89476);

  script_name(english:"Juniper Junos PIM Join Flood DoS (PSN-2013-01-808)");
  script_summary(english:"Checks model & version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the remote Junos device
has a denial of service vulnerability.  Receiving a large number of
specially crafted IPv4 or IPv6 PIM join messages in a Next-Generation
Multicast VPN (NGEN MVPN) environment can cause the routing daemon to
crash."
  );
  # http://www.juniper.net/alerts/viewalert.jsp?txtAlertNumber=PSN-2013-01-808
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dbfa89c0");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2013-01-808."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("junos.inc");
include("misc_func.inc");

fixes['10.0'] = '10.0S28';
fixes['10.4'] = '10.4R7';
fixes['11.1'] = '11.1R5';
fixes['11.2'] = '11.2R2';
fixes['11.4'] = '11.4R1';

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
check_model(model:model, flags:ALL_ROUTERS, exit_on_fail:TRUE);
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_warning(port:0, extra:report);
}
else security_warning(0);
