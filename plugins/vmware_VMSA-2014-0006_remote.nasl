#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87678);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/01/06 22:50:54 $");

  script_cve_id(
    "CVE-2010-5298",
    "CVE-2014-0198",
    "CVE-2014-0224",
    "CVE-2014-3470"
  );
  script_bugtraq_id(
    66801,
    67193,
    67898,
    67899
  );
  script_osvdb_id(
    105763,
    106531,
    107729,
    107731
  );
  script_xref(name:"VMSA", value:"2014-0006");
  script_xref(name:"CERT", value:"978508");

  script_name(english:"VMware ESXi Multiple OpenSSL Vulnerabilities (VMSA-2014-0006)");
  script_summary(english:"Checks the version and build numbers of the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi host is affected by multiple vulnerabilities 
in the OpenSSL third-party library :

  - A use-after-free error exists in the ssl3_read_bytes()
    function in file ssl/s3_pkt.c that is triggered when a
    second read is done to the function by multiple threads
    when SSL_MODE_RELEASE_BUFFERS is enabled. A
    man-in-the-middle attacker can exploit this to
    dereference already freed memory and inject arbitrary
    data into the SSL stream. (CVE-2010-5298)

  - A NULL pointer dereference flaw exists in the
    do_ssl3_write() function in file ssl/s3_pkt.c due to a
    failure to properly manage a buffer pointer during
    certain recursive calls when SSL_MODE_RELEASE_BUFFERS is
    enabled. A remote attacker can exploit this, by
    triggering an alert condition, to cause a denial of
    service. (CVE-2014-0198)

  - A flaw exists due to a failure to properly restrict
    processing of ChangeCipherSpec messages. A
    man-in-the-middle attacker can exploit this, via a
    crafted TLS handshake, to force the use of a zero-length
    master key in certain OpenSSL-to-OpenSSL communications,
    resulting in the session being hijacked and sensitive
    information being disclosed. (CVE-2014-0224)

  - A NULL pointer dereference flaw exists in the
    ssl3_send_client_key_exchange() function in file
    s3_clnt.c, when an anonymous ECDH cipher suite is used,
    that allows a remote attacker to cause a denial of
    service. (CVE-2014-3470)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2014-0006");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2014/000276.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESXi version 5.0 / 5.1 / 5.5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/09");
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

if ("ESXi" >!< rel)
  audit(AUDIT_OS_NOT, "VMware ESXi");

esx = "ESXi";

extract = eregmatch(pattern:"^ESXi (\d\.\d).*$", string:ver);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_APP_VER, "VMware ESXi");
else
  ver = extract[1];

fixes = make_array(
          "5.0", "1918656",
          "5.1", "1900470",
          "5.5", "1881737"
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

if (build < fix)
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
