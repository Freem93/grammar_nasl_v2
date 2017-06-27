#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55939);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/10/18 13:33:24 $");
  script_osvdb_id(77147);

  script_name(english:"Juniper Junos Multiple sfid Daemon Malformed Packet Remote DoS (PSN-2011-04-241)");
  script_summary(english:"Checks model & version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote switch has a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote device is a Juniper EX Series switch running Junos 11.1R1.
The sfid daemon on the line card may crash repeatedly due to improper
parsing of NetBIOS packets.

A remote attacker could exploit this to cause a denial of service."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?04e26402");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Junos 11.1S1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/26");
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

fixes['11.1'] = '11.1S1';

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

check_model(model:model, flags:EX_SERIES, exit_on_fail:TRUE);
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_warning(port:0, extra:report);
}
else security_warning(0);

