#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56769);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/10/18 13:33:24 $");

  script_bugtraq_id(50653);
  script_osvdb_id(76929);

  script_name(english:"Juniper Junos MPC Malformed Route Prefix Remote DoS (PSN-2011-08-327)");
  script_summary(english:"Checks model & version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote router has a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the remote Juniper
router has a denial of service vulnerability.  Receiving specific
route prefix install/delete actions (e.g., a BGP routing update) can
cause the router to crash.

This issue only affects MX Series routers with port concetrators based
on the Trio chipset."
  );
  # http://www.juniper.net/alerts/viewalert.jsp?actionBtn=Search&txtAlertNumber=PSN-2011-08-327&viewMode=view
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?25729063");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2011-08-327."
  );
 script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/08");
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

fixes['10.0'] = '10.0S18';
fixes['10.2'] = '10.2S10';
fixes['10.4'] = '10.4R6';
fixes['11.1'] = '11.1R4';
fixes['11.2'] = '11.2R1';

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

check_model(model:model, flags:MX_SERIES, exit_on_fail:TRUE);
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_warning(port:0, extra:report);
}
else security_warning(0);

