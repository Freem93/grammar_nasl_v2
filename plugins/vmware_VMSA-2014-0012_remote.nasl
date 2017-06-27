#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87681);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/01/06 22:50:54 $");

  script_cve_id(
    "CVE-2013-1752",
    "CVE-2013-2877",
    "CVE-2013-4238",
    "CVE-2014-0015",
    "CVE-2014-0138",
    "CVE-2014-0191"
  );
  script_bugtraq_id(
    61050,
    61738,
    63804,
    65270,
    66457,
    67233
  );
  script_osvdb_id(
    95032,
    96215,
    101381,
    101382,
    101383,
    101384,
    101385,
    101386,
    102715,
    104972,
    106710
  );
  script_xref(name:"VMSA", value:"2014-0012");

  script_name(english:"VMware ESXi Multiple Vulnerabilities (VMSA-2014-0012)");
  script_summary(english:"Checks the version and build numbers of the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi host is affected by multiple vulnerabilities :

  - Multiple denial of service vulnerabilities exist in
    Python function _read_status() in library httplib and
    in function readline() in libraries smtplib, ftplib,
    nntplib, imaplib, and poplib. A remote attacker can
    exploit these vulnerabilities to crash the module.
    (CVE-2013-1752)

  - A out-of-bounds read error exists in file parser.c in
    library libxml2 due to a failure to properly check the
    XML_PARSER_EOF state. An unauthenticated, remote
    attacker can exploit this, via a crafted document that
    abruptly ends, to cause an denial of service.
    (CVE-2013-2877)

  - A spoofing vulnerability exists in the Python SSL module
    in the ssl.match_hostname() function due to improper
    handling of the NULL character ('\0') in a domain name
    in the Subject Alternative Name field of an X.509
    certificate. A man-in-the-middle attacker can exploit
    this, via a crafted certificate issued by a legitimate
    certification authority, to spoof arbitrary SSL servers.
    (CVE-2013-4238)

  - cURL and libcurl are affected by a flaw related to the
    re-use of NTLM connections whenever more than one
    authentication method is enabled. An unauthenticated,
    remote attacker can exploit this, via a crafted request,
    to connect and impersonate other users. (CVE-2014-0015)

  - The default configuration in cURL and libcurl reuses the
    SCP, SFTP, POP3, POP3S, IMAP, IMAPS, SMTP, SMTPS, LDAP,
    and LDAPS connections. An unauthenticated, remote
    attacker can exploit this, via a crafted request, to 
    connect and impersonate other users. (CVE-2014-0138)

  - A flaw exists in the xmlParserHandlePEReference()
    function in file parser.c in libxml2 due to loading
    external entities regardless of entity substitution or
    validation being enabled. An unauthenticated, remote
    attacker can exploit this, via a crafted XML document,
    to exhaust resources, resulting in a denial of service.
    (CVE-2014-0191)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2014-0012");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2015/000287.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESXi version 5.0 / 5.1 / 5.5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/27");
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
          "5.5", "See vendor"
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
