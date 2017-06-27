#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89676);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/03/07 14:48:53 $");

  script_cve_id(
    "CVE-2010-1323",
    "CVE-2010-1324",
    "CVE-2010-2240",
    "CVE-2010-4020",
    "CVE-2010-4021",
    "CVE-2011-1785",
    "CVE-2011-1786"
  );
  script_bugtraq_id(
    42505,
    45116,
    45117,
    45118,
    45122,
    47625,
    47627
  );
  script_osvdb_id(
    67237,
    69607,
    69608,
    69609,
    69610,
    72118,
    73742
  );
  script_xref(name:"VMSA", value:"2011-0007");

  script_name(english:"VMware ESX / ESXi Multiple Vulnerabilities (VMSA-2011-0007) (remote check)");
  script_summary(english:"Checks the ESX / ESXi version and build number.");

  script_set_attribute(attribute:"synopsis",  value:
"The remote VMware ESX / ESXi host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX / ESXi host is missing a security-related patch.
It is, therefore, affected by multiple vulnerabilities :

  - Multiple forgery vulnerabilities exist in the bundled
    version of MIT Kerberos 5 (krb5). An attacker can
    exploit these issues to impersonate a client, escalate
    privileges, and disclose sensitive information.
    (CVE-2010-1323, CVE-2010-1324, CVE-2010-4020,
    CVE-2010-4021)

  - A local arbitrary code execution vulnerability exists in
    the Kernel in the do_anonymous_page() function due to
    improper separation of the stack and the heap. A local
    attacker can exploit this vulnerability to execute
    arbitrary code. (CVE-2010-2240)

  - A denial of service vulnerability exists that allows a
    remote attacker to exhaust available sockets, preventing
    further connections. (CVE-2011-1785)

  - A denial of service vulnerability exists in the bundled
    version of lsassd in Likewise Open. A remote attacker
    can exploit this, via an Active Directory login attempt
    that provides a username containing an invalid byte
    sequence, to cause a daemon crash. (CVE-2011-1786)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2011-0007");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2011/000133.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESX version 4.0 / 4.1 or ESXi version 4.0 / 4.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");
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
esx = '';

if ("ESX" >!< rel)
  audit(AUDIT_OS_NOT, "VMware ESX/ESXi");

extract = eregmatch(pattern:"^(ESXi?) (\d\.\d).*$", string:ver);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_APP_VER, "VMware ESX/ESXi");
else
{
  esx = extract[1];
  ver = extract[2];
}

# fixed build numbers are the same for ESX and ESXi
fixes = make_array(
          "4.0", "392990",
          "4.1", "381591"
        );

fix = FALSE;
fix = fixes[ver];

# get the build before checking the fix for the most complete audit trail
extract = eregmatch(pattern:'^VMware ESXi?.* build-([0-9]+)$', string:rel);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_BUILD, "VMware " + esx, ver);

build = int(extract[1]);

# if there is no fix in the array, fix is FALSE
if (!fix)
  audit(AUDIT_INST_VER_NOT_VULN, "VMware " + esx, ver, build);

if (build < fix)
{

  report = '\n  Version         : ' + esx + " " + ver +
           '\n  Installed build : ' + build +
           '\n  Fixed build     : ' + fix +
           '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "VMware " + esx, ver, build);
