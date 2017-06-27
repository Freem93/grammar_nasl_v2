#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81085);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/24 13:12:23 $");

  script_cve_id(
    "CVE-2014-3513",
    "CVE-2014-3566",
    "CVE-2014-3567",
    "CVE-2014-3568",
    "CVE-2014-3660",
    "CVE-2014-8370",
    "CVE-2015-1044"
  );
  script_bugtraq_id(
    70574,
    70584,
    70585,
    70586,
    70644,
    72336,
    72338
  );
  script_osvdb_id(
    113251,
    113373,
    113374,
    113377,
    113389
  );
  script_xref(name:"CERT", value:"577193");
  script_xref(name:"VMSA", value:"2015-0001");

  script_name(english:"ESXi 5.5 < Build 2352327 Multiple Vulnerabilities (remote check) (POODLE)");
  script_summary(english:"Checks the ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi 5.5 host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi host is version 5.5 prior to build 2352327. It
is, therefore, affected by the following vulnerabilities :

  - An error exists related to DTLS SRTP extension handling
    and specially crafted handshake messages that can allow
    denial of service attacks via memory leaks.
    (CVE-2014-3513)

  - An error exists related to the way SSL 3.0 handles
    padding bytes when decrypting messages encrypted using
    block ciphers in cipher block chaining (CBC) mode. A
    man-in-the-middle attacker can decrypt a selected byte
    of a cipher text in as few as 256 tries if they are able
    to force a victim application to repeatedly send the
    same data over newly created SSL 3.0 connections. This
    is also known as the 'POODLE' issue. (CVE-2014-3566)

  - An error exists related to session ticket handling that
    can allow denial of service attacks via memory leaks.
    (CVE-2014-3567)

  - An error exists related to the build configuration
    process and the 'no-ssl3' build option that allows
    servers and clients to process insecure SSL 3.0
    handshake messages. (CVE-2014-3568)

  - A denial of service vulnerability in libxml2 due to
    entity expansion even when entity substitution is
    disabled. A remote attacker, using a crafted XML
    document containing  larger number of nested entity
    references, can cause the consumption of CPU resources.
    (CVE-2014-3660)

  - An unspecified privilege escalation vulnerability.
    (CVE-2014-8370)

  - An unspecified denial of service vulnerability due to an
    input validation issue in the VMware Authorization
    process (vmware-authd). (CVE-2015-1044)");

  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2015-0001.html");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Apply patch ESXi550-201403102-SG and ESXi550-201501101-SG for ESXi
5.5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("Host/VMware/version");
rel = get_kb_item_or_exit("Host/VMware/release");

if ("ESXi" >!< rel) audit(AUDIT_OS_NOT, "ESXi");
if ("VMware ESXi 5.5" >!< rel) audit(AUDIT_OS_NOT, "ESXi 5.5");

match = eregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) exit(1, 'Failed to extract the ESXi build number.');

build       = int(match[1]);
fixed_build = 2352327;

if (build < fixed_build)
{
  if (report_verbosity > 0)
  {
    report = '\n  ESXi version    : ' + ver +
             '\n  Installed build : ' + build +
             '\n  Fixed build     : ' + fixed_build +
             '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware ESXi", ver - "ESXi " + " build " + build);
