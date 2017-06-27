#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59987);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/09/08 14:15:23 $");
  script_osvdb_id(85341);

  script_name(english:"Juniper Junos SYN Cookie Protection DoS (PSN-2012-07-643)");
  script_summary(english:"Checks version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device has a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the SYN cookie
protection implementation of the remote Junos system has a denial of
service vulnerability.  If SYN flood protection is enabled and the SYN
cookie protection threshold is exceeded, the server responds to
connections with an RST, causing the connection to be closed."
  );
  # http://www.juniper.net/alerts/viewalert.jsp?actionBtn=Search&txtAlertNumber=PSN-2012-07-643&viewMode=view
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dfff0837");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2012-07-643."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/17");
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

fixes['11.4'] = '11.4R4';
fixes['12.1'] = '12.1R2';

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_hole(port:0, extra:report);
}
else security_hole(0);
