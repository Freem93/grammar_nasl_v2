#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89114);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id(
    "CVE-2009-0844",
    "CVE-2009-0845",
    "CVE-2009-0846"
  );
  script_bugtraq_id(
    34408,
    34257,
    34409
  );
  script_osvdb_id(
    52963,
    53383,
    53384
  );
  script_xref(name:"VMSA", value:"2009-0008");  

  script_name(english:"VMware ESX Multiple Vulnerabilities (VMSA-2009-0008) (remote check)");
  script_summary(english:"Checks the ESX version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX host is missing a security-related patch. It is,
therefore, affected by multiple vulnerabilities :

  - An out-of-bounds read error exists in the MIT Kerberos
    SPNEGO implementation in the get_input_token() function.
    A remote attacker can exploit this, via a crafted
    length value, to cause a denial of service or to obtain
    access to sensitive information. (CVE-2009-0844)

  - A NULL pointer dereference flaw exists in MIT Kerberos
    in the spnego_gss_accept_sec_context() function when
    SPNEGO is used. A remote attacker can exploit this, via
    invalid ContextFlags data in the 'reqFlags' field within
    a 'negTokenInit' token, to cause a denial of service.
    (CVE-2009-0845)

  - A flaw exists in the MIT Kerberos ASN.1 GeneralizedTime
    decoder in the asn1_decode_generaltime() function. A
    remote attacker can exploit this, via vectors involving
    invalid DER encoding, to free an uninitialized pointer,
    resulting in a denial of service or the execution of
    arbitrary code. (CVE-2009-0846)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2009-0008");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESX version 3.5 / 4.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/30");
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
fixes["ESX 3.5"]  = 169697;
fixes["ESX 4.0"]  = 175625;

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

  security_report_v4(extra:report, port:port, severity:SECURITY_HOLE);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "VMware " + version + " build " + build);
  