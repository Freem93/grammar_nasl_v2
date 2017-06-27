#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89109);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/03/04 16:00:57 $");

  script_cve_id(
    "CVE-2010-4008",
    "CVE-2011-0216",
    "CVE-2011-1944",
    "CVE-2011-2834",
    "CVE-2011-3191",
    "CVE-2011-3905",
    "CVE-2011-3919",
    "CVE-2011-4348",
    "CVE-2012-0028"
  );
  script_bugtraq_id(
    44779,
    48056,
    48832,
    49295,
    49658,
    51084,
    51300,
    51363,
    51947
  );
  script_osvdb_id(
    69205,
    73248,
    73994,
    74910,
    75560,
    77707,
    78148,
    78303,
    79098
  );
  script_xref(name:"VMSA", value:"2012-0008");

  script_name(english:"VMware ESX Service Console Multiple Vulnerabilities (VMSA-2012-0008) (remote check)");
  script_summary(english:"Checks the remote ESX host's version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESX host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX host is missing a security-related patch. It is,
therefore, affected by multiple vulnerabilities, including remote code
execution vulnerabilities, in the following components :

  - COS kernel
  - libxml2");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2012-0008.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");
  script_require_ports("Host/VMware/vsphere");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("Host/VMware/version");
rel = get_kb_item_or_exit("Host/VMware/release");
port = get_kb_item_or_exit("Host/VMware/vsphere");

esx = "ESX/ESXi";

extract = eregmatch(pattern:"^(ESXi?) (\d\.\d).*$", string:ver);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_APP_VER, esx);
else
{
  esx = extract[1];
  ver = extract[2];
}

product = "VMware " + esx;

# fix builds                                                                   
fixes = make_array(
  "ESX 4.1",  659051
);

key = esx + ' ' + ver;
fix = NULL;
fix = fixes[key];

bmatch = eregmatch(pattern:'^VMware ESXi?.*build-([0-9]+)$', string:rel);
if (empty_or_null(bmatch))
  audit(AUDIT_UNKNOWN_BUILD, product, ver);

build = int(bmatch[1]);

if (!fix)
  audit(AUDIT_INST_VER_NOT_VULN, product, ver, build);

if (build < fix)
{
  # properly spaced label
  if ("ESXi" >< esx) ver_label = ' version    : ';
  else ver_label = ' version     : ';
  report = '\n  ' + esx + ver_label + ver +
           '\n  Installed build : ' + build +
           '\n  Fixed build     : ' + fix +
           '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, product, ver, build);
