#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87676);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/19 18:10:50 $");

  script_cve_id(
    "CVE-2014-0076",
    "CVE-2014-0160"
  );
  script_bugtraq_id(
    66363,
    66690
  );
  script_osvdb_id(
    104810,
    105465
  );
  script_xref(name:"VMSA", value:"2014-0004");
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");

  script_name(english:"VMware ESXi Multiple OpenSSL Vulnerabilities (VMSA-2014-0004) (Heartbleed)");
  script_summary(english:"Checks the version and build numbers of the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi host is affected by multiple vulnerabilities 
in the OpenSSL third-party library :

  - A flaw exist in the Elliptic Curve Digital Signature
    Algorithm (ECDSA) implementation due to a failure to
    insure that certain swap operations have a constant-time
    behavior. An attacker can exploit this to obtain the
    ECDSA nonces by using a FLUSH+RELOAD cache side-channel
    attack. (CVE-2014-0076)

  - An out-of-bounds read error, known as Heartbleed, exists
    in the TLS/DTLS implementation due to improper handling
    of TLS heartbeat extension packets. A remote attacker,
    using crafted packets, can trigger a buffer over-read,
    resulting in the disclosure of up to 64KB of process
    memory, which contains sensitive information such as
    primary key material, secondary key material, and other
    protected content. (CVE-2014-0160)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2014-0004");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2014/000244.html");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"http://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESXi version 5.5 / 5.5 U1. Additional remediation steps
may also need to be performed after applying the patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.5");
  script_set_attribute(attribute:"in_the_news", value:"true");
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

if ("ESXi" >!< rel)
  audit(AUDIT_OS_NOT, "VMware ESXi");

extract = eregmatch(pattern:"^ESXi (\d\.\d).*$", string:ver);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_APP_VER, "VMware ESXi");
else
  ver = extract[1];

low_fix = 1746018; #5.5
high_fix = 1746974; #5.5U1

fix = FALSE;
if (ver == "5.5")
  fix = high_fix;

# get the build before checking the fix for the most complete audit trail
extract = eregmatch(pattern:'^VMware ESXi.* build-([0-9]+)$', string:rel);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_BUILD, "VMware ESXi", ver);

build = int(extract[1]);

# if there is no fix in the array, fix is FALSE
if(!fix)
  audit(AUDIT_INST_VER_NOT_VULN, "VMware ESXi", ver, build);

if (build < fix && build != low_fix)
{
  fix = low_fix + " / " + fix;

  if (report_verbosity > 0)
  {
    report = '\n  Version         : ESXi '  + ver +
             '\n  Installed build : ' + build +
             '\n  Fixed build     : ' + fix +
             '\n';
    security_hole(port:port, extra:report);
  }
  else
    security_hole(port:port);

  exit(0);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "VMware ESXi", ver, build);
