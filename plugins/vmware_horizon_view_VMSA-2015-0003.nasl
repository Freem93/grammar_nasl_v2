#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82741);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/02/10 22:03:56 $");

  script_cve_id(
    "CVE-2014-3566",
    "CVE-2014-6549",
    "CVE-2014-6585",
    "CVE-2014-6587",
    "CVE-2014-6591",
    "CVE-2014-6593",
    "CVE-2014-6601",
    "CVE-2015-0383",
    "CVE-2015-0395",
    "CVE-2015-0400",
    "CVE-2015-0403",
    "CVE-2015-0406",
    "CVE-2015-0407",
    "CVE-2015-0408",
    "CVE-2015-0410",
    "CVE-2015-0412",
    "CVE-2015-0413",
    "CVE-2015-0421",
    "CVE-2015-0437",
    "CVE-2015-3269",
    "CVE-2015-5255"
  );
  script_bugtraq_id(
    70574,
    72132,
    72136,
    72137,
    72140,
    72142,
    72146,
    72148,
    72150,
    72154,
    72155,
    72159,
    72162,
    72165,
    72168,
    72169,
    72173,
    72175,
    72176,
    76394,
    77626
  );
  script_osvdb_id(
    113251,
    117224,
    117225,
    117226,
    117227,
    117228,
    117229,
    117230,
    117231,
    117232,
    117233,
    117234,
    117235,
    117236,
    117237,
    117238,
    117239,
    117240,
    117241,
    126408,
    130384
  );
  script_xref(name:"CERT", value:"577193");
  script_xref(name:"VMSA", value:"2015-0003");
  script_xref(name:"VMSA", value:"2015-0008");

  script_name(english:"VMware Horizon View Multiple Vulnerabilities (VMSA-2015-0003) (VMSA-2015-0008) (POODLE)");
  script_summary(english:"Checks the version of VMware Horizon View.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The VMware Horizon View installed on the remote Windows host is
version 5.x prior to 5.3.4 or version 6.x prior to 6.1. It is,
therefore, affected by the following vulnerabilities :

  - A man-in-the-middle (MitM) information disclosure
    vulnerability, known as POODLE, exists due to the way
    SSL 3.0 handles padding bytes when decrypting messages
    encrypted using block ciphers in cipher block chaining
    (CBC) mode. A MitM attacker can decrypt a selected byte
    of a cipher text in as few as 256 tries if they are able
    to force a victim application to repeatedly send the
    same data over newly created SSL 3.0 connections.
    (CVE-2014-3566)

  - An XML external entity (XXE) injection vulnerability
    exists in the included Flex BlazeDS component due to an
    incorrect configuration of the XML parser that allows
    external XML entities to be accepted from untrusted
    sources. An unauthenticated, remote attacker can exploit
    this vulnerability, via a via a crafted AMF message, to
    gain access to sensitive information. (CVE-2015-3269)

  - A flaw exists in the bundled Adobe ColdFusion and
    LiveCycle Data Services components related to request
    handling between a user and the server. A remote
    attacker can exploit this, via a specially crafted
    request, to bypass access restrictions (e.g. host or
    network ACLs), conduct port scanning of internal
    networks, enumerate internal hosts, or possibly invoke
    additional protocols (e.g. Gopher, TFTP).
    (CVE-2015-5255)

Additionally, unspecified vulnerabilities also exist in the following
bundled Java components :

  - 2D (CVE-2014-6585, CVE-2014-6591)

  - Deployment (CVE-2015-0403, CVE-2015-0406)

  - Hotspot (CVE-2014-6601, CVE-2015-0383, CVE-2015-0395,
    CVE-2015-0437)

  - Installation (CVE-2015-0421)

  - JAX-WS (CVE-2015-0412)

  - JSSE (CVE-2014-6593)

  - Libraries (CVE-2014-6549, CVE-2014-6587, CVE-2015-0400)

  - RMI (CVE-2015-0408)

  - Security (CVE-2015-0410)

  - Serviceability (CVE-2015-0413)

  - Swing (CVE-2015-0407)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2015-0003");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2015-0008");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2015/Apr/5");
  # http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c02f1515");
  # Java SE JDK and JRE 7 Update 75
  # http://www.oracle.com/technetwork/java/javase/7u75-relnotes-2389086.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?12e35b07");
  # Java SE JDK and JRE 6 Update 91
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Horizon View version 5.3.4 / 6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/13");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:horizon_view");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("vmware_horizon_view_installed.nbin");
  script_require_keys("installed_sw/VMware Horizon View");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "VMware Horizon View";
install  = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
path     = install['path'];
version  = install['version'];

if (version =~ "^5([^0-9]|$)")
  fix = "5.3.4";
else if (version =~ "^6([^0-9]|$)")
  fix = "6.1";
else
  audit(AUDIT_NOT_INST, app_name + "5.x or 6.x");

if (
  version =~ "^5(\.3)?$"
  ||
  version == "6"
)
  audit(AUDIT_VER_NOT_GRANULAR, app_name, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port:port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
