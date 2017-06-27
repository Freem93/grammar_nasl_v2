#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89664);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/03/07 14:48:53 $");

  script_cve_id("CVE-2012-5134");
  script_bugtraq_id(56684);
  script_osvdb_id(87882);
  script_xref(name:"VMSA", value:"2013-0004");

  script_name(english:"VMware ESX / ESXi libxml2 RCE (VMSA-2013-0004) (remote check)");
  script_summary(english:"Checks the version and build numbers of the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESX / ESXi host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX / ESXi host is missing a security-related patch.
It is, therefore, affected by affected by a heap-based underflow
condition in the bundled libxml2 library due to incorrect parsing of
strings not containing an expected space. A remote attacker can
exploit this, via a specially crafted XML document, to cause a denial
of service condition or the execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2013-0004");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESX version 4.0 / 4.1 or ESXi version 4.0 / 4.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");
  script_require_ports("Host/VMware/vsphere");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit("Host/VMware/version");
rel   = get_kb_item_or_exit("Host/VMware/release");
port  = get_kb_item_or_exit("Host/VMware/vsphere");
esx   = '';
build = 0;
fix   = FALSE;

if ("ESX" >!< rel)
  audit(AUDIT_OS_NOT, "VMware ESX/ESXi");

extract = eregmatch(pattern:"^(ESXi?) (\d\.\d).*$", string:ver);
if (empty_or_null(extract))
  audit(AUDIT_UNKNOWN_APP_VER, "VMware ESX/ESXi");

esx = extract[1];
ver = extract[2];

extract = eregmatch(pattern:'^VMware ESXi?.* build-([0-9]+)$', string:rel);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_BUILD, "VMware " + esx, ver);

build = int(extract[1]);

fixes = make_array(
    "4.0", 1070634,
    "4.1", 1050704
);

fix = fixes[ver];

if (!fix)
  audit(AUDIT_INST_VER_NOT_VULN, esx, ver, build);

if (build < fix)
{
  report = '\n  Version         : ' + esx + " " + ver +
           '\n  Installed build : ' + build +
           '\n  Fixed build     : ' + fix +
           '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
  exit(0);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "VMware " + esx, ver, build);
