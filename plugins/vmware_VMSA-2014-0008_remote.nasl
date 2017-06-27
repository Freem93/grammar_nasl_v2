#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87679);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/06 17:22:02 $");

  script_cve_id(
    "CVE-2013-0242",
    "CVE-2013-1914"
  );
  script_bugtraq_id(
    57638,
    58839
  );
  script_osvdb_id(
    89747,
    92038
  );
  script_xref(name:"VMSA", value:"2014-0008");

  script_name(english:"VMware ESXi Multiple DoS (VMSA-2014-0008)");
  script_summary(english:"Checks the version and build numbers of the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote ESXi host is affected by multiple denial of service
vulnerabilities in the glibc library :

  - A buffer overflow condition exists in the
    extend_buffers() function in file posix/regexec.c due to
    improper validation of user-supplied input when handling
    multibyte characters in a regular expression. An
    unauthenticated, remote attacker can exploit this, via
    a crafted regular expression, to corrupt the memory,
    resulting in a denial of service. (CVE-2013-0242)

  - A stack-based buffer overflow condition exists in the
    getaddrinfo() function in file posix/getaddrinfo.c due
    to improper validation of user-supplied input during the
    handling of domain conversion results. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service by using a crafted host name
    or IP address that triggers a large number of domain
    conversion results. (CVE-2013-1914)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2014-0008");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2014/000282.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESXi version 5.0 / 5.1 / 5.5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
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

pci = FALSE;
pci = get_kb_item("Settings/PCI_DSS");

if ("ESXi" >!< rel)
  audit(AUDIT_OS_NOT, "VMware ESXi");

esx = "ESXi";

extract = eregmatch(pattern:"^ESXi (\d\.\d).*$", string:ver);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_APP_VER, "VMware ESXi");
else
  ver = extract[1];

fixes = make_array(
          "5.0", "See vendor",
          "5.1", "2323236",
          "5.5", "2068190"
        );

fix = FALSE;
fix = fixes[ver];

# get the build before checking the fix for the most complete audit trail
extract = eregmatch(pattern:'^VMware ESXi.* build-([0-9]+)$', string:rel);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_BUILD, "VMware ESXi", ver);

build = int(extract[1]);

# if there is no fix in the array, fix is FALSE
if(!fix)
  audit(AUDIT_INST_VER_NOT_VULN, "VMware ESXi", ver, build);

if (!pci && fix == "See vendor")
  audit(AUDIT_PCI);

vuln = FALSE;

# This is for PCI reporting
if (pci && fix == "See vendor")
  vuln = TRUE;
else if (build < fix )
  vuln = TRUE;

if (vuln)
{
  if (report_verbosity > 0)
  {
    report = '\n  Version         : ESXi '  + ver +
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
  audit(AUDIT_INST_VER_NOT_VULN, "VMware ESXi", ver, build);
