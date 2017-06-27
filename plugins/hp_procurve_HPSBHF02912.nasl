#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71378);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

  script_cve_id("CVE-2013-4806");
  script_bugtraq_id(61691);
  script_osvdb_id(95909);
  script_xref(name:"HP", value:"HPSBHF02912");
  script_xref(name:"HP", value:"SSRT101224");
  script_xref(name:"HP", value:"emr_na-c03880910");
  script_xref(name:"CERT", value:"229804");

  script_name(english:"HP Multiple Network Products Remote Information Disclosure and DoS (HPSBHF02912)");
  script_summary(english:"Checks model number to determine presence of flaw");

  script_set_attribute(attribute: "synopsis", value:"The remote host is missing a vendor-supplied software update.");
  script_set_attribute(attribute: "description", value:
"The remote HP router or switch could be missing a vendor-supplied
update that corrects an issue that a malicious attacker could remotely
exploit in order to cause a disclosure of information or denial of
service (DoS).");
  script_set_attribute(attribute: "solution", value:"Apply the vendor-specified update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  # https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c03880910
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8f5f73d");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:procurve_switch");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:3com_router");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:h3c_ethernet_switch");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("ssh_get_info.nasl", "hp_procurve_version.nasl");
  script_require_keys("Host/HP_Switch", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item('Host/HP_Switch')) exit(0, "This is not an HP Switch.");

rev = get_kb_item_or_exit("Host/HP_Switch/SoftwareRevision");
if ( isnull(rev) || rev == "unknown" ) exit(0, "The software revision for the device could not be obtained.");

model = get_kb_item_or_exit("Host/HP_Switch/Model");
if ( isnull(model) || model == "unknown" ) exit(0, "The model number could not be obtained.");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

flag = 0;
fix_version = "";

# check the affected models
temp_fix_version="R5000_3.14p14";
products = make_list(
  "JD935A",
  "JD943A",
  "JD944A",
  "JD945A",
  "JD946A"
);
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="R301X_1.40.23";
products = make_list(
  "JD916A",
  "JD919A"
);
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="S5600_3.10.R1702P39";
products = make_list(
  "JD391A",
  "JD392A",
  "JD393A",
  "JD394A",
  "JD395A",
  "S5600-26C",
  "S5600-26C-PWR",
  "S5600-26F",
  "S5600-50C",
  "S5600-50C-PWR"
);
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="E5500G_03.03.02p19";
products = make_list(
  "JE088A",
  "JE089A",
  "JE090A",
  "JE091A",
  "JE092A",
  "JE093A",
  "JE094A",
  "JE095A",
  "JE096A",
  "JE097A",
  "JF551A",
  "JF552A",
  "JF553A"
);
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="E5500_03.03.02p19";
products = make_list(
  "JE099A",
  "JE100A",
  "JE101A",
  "JE102A",
  "JE103A",
  "JE104A",
  "JE105A",
  "JE106A",
  "JE107A",
  "JE108A",
  "JE109A",
  "JE110A"
);
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="S3600.EI_3.10.R1702P34";
products = make_list(
  "JD326A",
  "JD328A",
  "JD331A",
  "JD333A",
  "JD334A",
  "S3600-28F-EI",
  "S3600-28P-EI",
  "S3600-28P-PWR-EI",
  "S3600-52P-EI",
  "S3600-52P-PWR-EI"
);
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="E.11.38";
products = make_list(
  "J4819A",
  "J4848A",
  "J4848B",
  "J4849A",
  "J4849B",
  "J4850A",
  "J8166A",
  "J8167A"
);

foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="M.10.99";
products = make_list(
  "J4905A",
  "J4906A"
);
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="M.08.140";
products = make_list(
  "J8433A",
  "J8474A"
);
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

# report as needed
if (flag)
{
  report = '\n' + 'The remote HP system is not patched :' +
           '\n' +
           '\n' + '  Model # : ' + model +
           '\n' +
           '\n' + '    Current software revision  : ' + rev +
           '\n' + '    Suggested software version : ' + fix_version +
           '\n';
  security_hole(port:0, extra:report);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
