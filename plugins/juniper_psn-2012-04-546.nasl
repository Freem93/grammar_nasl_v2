#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58875);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/08/28 13:51:52 $");
  script_osvdb_id(82819);

  script_name(english:"Juniper Junos MPLS DoS (PSN-2012-04-546)");
  script_summary(english:"Checks model & version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote router has a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the version of Junos
running on the remote host has a denial of service vulnerability.
When MPLS is enabled, receiving a high rate of Pseudo Wire (l2vpn or
l2circuit) control words from an adjacent node can cause the routing
engine (RE) to become overloaded.  This could result in an RE
switchover, or a reboot in single RE environments."
  );
  # http://www.juniper.net/alerts/viewalert.jsp?actionBtn=Search&txtAlertNumber=PSN-2012-04-546&viewMode=view
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e80736ee");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2012-04-546."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/25");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("misc_func.inc");
include("junos.inc");

fixes['10.4'] = '10.4R9';
fixes['11.2'] = '11.2R5';
fixes['11.3'] = '11.3R4';
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

