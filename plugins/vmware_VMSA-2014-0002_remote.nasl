#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87674);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/01/06 22:50:54 $");

  script_cve_id(
    "CVE-2013-4332",
    "CVE-2013-5211"
  );
  script_bugtraq_id(
    62324,
    64692
  );
  script_osvdb_id(
    97246,
    97247,
    97248,
    101576
  );
  script_xref(name:"VMSA", value:"2014-0002");
  script_xref(name:"CERT", value:"348126");

  script_name(english:"VMware ESX / ESXi Multiple Vulnerabilities (VMSA-2014-0002)");
  script_summary(english:"Checks the version and build numbers of the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESX / ESXi host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX / ESXi host is affected by multiple
vulnerabilities :

  - Multiple integer overflow conditions exist in the glibc
    package in file malloc/malloc.c. An unauthenticated,
    remote attacker can exploit these to cause heap memory
    corruption by passing large values to the pvalloc(),
    valloc(), posix_memalign(), memalign(), or
    aligned_alloc() functions, resulting in a denial of
    service. (CVE-2013-4332)

  - A distributed denial of service (DDoS) vulnerability
    exists in the NTP daemon due to improper handling of the
    'monlist' command. A remote attacker can exploit this,
    via a forged request to an affected NTP server, to cause
    an amplified response to the intended target of the DDoS
    attack. (CVE-2013-5211)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2014-0002");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2014/000281.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESX version 4.0 / 4.1 and ESXi version 4.0 / 4.1 / 5.0 /
5.1 / 5.5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.5");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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
          "4.0", "1682696",
          "4.1", "1682698",
          "5.0", "1749766",
          "5.1", "1743201",
          "5.5", "1623387"
        );

full_fixes = make_array(
              "5.0", "1851670",
              "5.1", "1743533"
           );

fix = FALSE;
fix = fixes[ver];
full_fix = FALSE;
full_fix = full_fixes[ver];

# get the build before checking the fix for the most complete audit trail
extract = eregmatch(pattern:'^VMware ESXi?.* build-([0-9]+)$', string:rel);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_BUILD, "VMware " + esx, ver);

build = int(extract[1]);

# if there is no fix in the array, fix is FALSE
if(!fix)
  audit(AUDIT_INST_VER_NOT_VULN, esx, ver, build);

if (build < fix)
{
  if (full_fix)
    fix = fix + " / " + full_fix;

  if (report_verbosity > 0)
  {
    report = '\n  Version         : ' + esx + " " + ver +
             '\n  Installed build : ' + build +
             '\n  Fixed build     : ' + fix +
             '\n';
    security_warning(port:port, extra:report);
  }
  else
    security_warning(port:port);

  exit(0);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "VMware " + esx, ver, build);
