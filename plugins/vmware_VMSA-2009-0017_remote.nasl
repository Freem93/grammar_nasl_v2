#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89118);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/03/04 16:00:57 $");

  script_cve_id("CVE-2009-3731");
  script_bugtraq_id(37346);
  script_osvdb_id(
    61306,
    61308,
    61049,
    61305,
    61307
  );
  script_xref(name:"VMSA", value:"2009-0017");

  script_name(english:"VMware ESX WebWorks Help Multiple XSS (VMSA-2009-0017) (remote check)");
  script_summary(english:"Checks the ESX version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX host is missing a security-related patch. It is,
therefore, affected by multiple cross-site scripting (XSS)
vulnerabilities in WebWorks Help due to improper sanitization of
user-supplied input to unspecified parameters or to messages used in
topic links. A remote attacker can exploit these to inject arbitrary
script code or HTML into the user's browser session.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2009-0017");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESX version 4.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");
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

version = get_kb_item_or_exit("Host/VMware/version");
release = get_kb_item_or_exit("Host/VMware/release");
port    = get_kb_item_or_exit("Host/VMware/vsphere");

fixes = make_array();
fixes["ESX 4.0"]  = 208167;

matches = eregmatch(pattern:'^VMware (ESXi?).*build-([0-9]+)$', string:release);
if (empty_or_null(matches))
  exit(1, 'Failed to extract the ESX / ESXi build number.');

type  = matches[1];
build = int(matches[2]);

fixed_build = fixes[version];

if (!isnull(fixed_build) && build < fixed_build)
{
  padding = crap(data:" ", length:8 - strlen(type)); # Spacing alignment

  report = '\n  ' + type + ' version' + padding + ': ' + version +
           '\n  Installed build : ' + build +
           '\n  Fixed build     : ' + fixed_build +
           '\n';

  security_report_v4(extra:report, port:port, severity:SECURITY_WARNING, xss:TRUE);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "VMware " + version + " build " + build);
