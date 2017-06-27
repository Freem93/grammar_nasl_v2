#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59994);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  #script_cve_id("CVE-2011-3414");  # juniper lists this CVE in their advisory, but this CVE is specific to ASP.NET
  #script_bugtraq_id(51186); # ASP.NET
  #script_osvdb_id(78057); # ASP.NET
  script_osvdb_id(85336);
  script_xref(name:"CERT", value:"903934");

  script_name(english:"Juniper Junos J-Web Hash Collision DoS (PSN-2012-07-650)");
  script_summary(english:"checks version and model");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device has a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the remote Junos
device has a denial of service vulnerability in the J-Web component.
It is possible to send requests to the web server that result in hash
collisions, resulting in CPU consumption."
  );
  # http://www.juniper.net/alerts/viewalert.jsp?actionBtn=Search&txtAlertNumber=PSN-2012-07-650&viewMode=view
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6caa34c1");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2012-07-650."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/17");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("misc_func.inc");
include("junos.inc");

fixes['10.0'] = '10.0S25';
fixes['10.4'] = '10.4R10';
fixes['11.2'] = '11.2R7';
fixes['11.3'] = '11.3R6';
fixes['11.4'] = '11.4R3';
fixes['12.1'] = '12.1R2';

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_hole(port:0, extra:report);
}
else security_hole(0);
