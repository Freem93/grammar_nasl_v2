#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56770);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/10/18 13:33:24 $");
  script_osvdb_id(77153);

  script_name(english:"Juniper Junos Next-Gen MVPN Senario Malformed Message Handling Remote DoS (PSN-2011-10-391)");
  script_summary(english:"Checks model & version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote router has a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the remote Juniper
router has a denial of service vulnerability.  In a Next Generation
MVPN scenario, a kernel memory buffer could get corrupted when the
router receives a bootstrap or auto-RP message larger than 204 bytes,
causing the kernel to crash every time a packet is received.

This issue only occurs in Next-Gen MVPN scenarios that use Ingress
Replication as the P-tunnel type and has Auto-RP or Bootstrap as the
group-to-RP mapping mechanism."
  );
  # http://www.juniper.net/alerts/viewalert.jsp?actionBtn=Search&txtAlertNumber=PSN-2011-10-391&viewMode=view
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec5749e8");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2011-10-391."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/10");
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

fixes['9.3'] = '9.3S25';
fixes['10.0'] = '10.0S19';
fixes['10.4'] = '10.4S7';
fixes['11.1'] = '11.1S5';
fixes['11.2'] = '11.2S2';
fixes['11.3'] = '11.3R2';

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

check_model(model:model, flags:MX_SERIES | J_SERIES | T_SERIES | M_SERIES, exit_on_fail:TRUE);
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_hole(port:0, extra:report);
}
else security_hole(0);

