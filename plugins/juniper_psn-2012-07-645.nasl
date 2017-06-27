#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59989);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/10/27 15:03:54 $");

  script_cve_id("CVE-2012-2110", "CVE-2012-2131");
  script_bugtraq_id(53158, 53212);
  script_osvdb_id(81223, 82110);
  script_xref(name:"EDB-ID", value:"18756");

  script_name(english:"Juniper Junos OpenSSL ASN.1 Memory Corruption (PSN-2012-07-645)");
  script_summary(english:"Checks version & model");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote router has a memory corruption vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the remote Junos
router is using an outdated version of OpenSSL. Parsing malformed
ASN.1 encoded data can result in memory corruption. This vulnerability
can be triggered by attempting to parse untrusted data (e.g., an X.509
certificate)."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Apr/210");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20120419.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20120424.txt");
  # http://www.juniper.net/alerts/viewalert.jsp?actionBtn=Search&txtAlertNumber=PSN-2012-07-645&viewMode=view
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df5606ad");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2012-07-645."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/19");
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

fixes['10.4'] = '10.4S10';
fixes['11.4'] = '11.4R4';
fixes['12.1'] = '12.1R2';

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
check_model(model:model, flags:ALL_ROUTERS, exit_on_fail:TRUE);
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_hole(port:0, extra:report);
}
else security_hole(0);
