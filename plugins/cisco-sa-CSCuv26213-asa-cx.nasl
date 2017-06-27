#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86104);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/12 18:38:05 $");

  script_cve_id("CVE-2015-1793");
  script_bugtraq_id(75652);
  script_osvdb_id(124300);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv26213");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150710-openssl");

  script_name(english:"Cisco ASA Next-Generation Firewall OpenSSL Alternative Chains Certificate Forgery (cisco-sa-20150710-openssl)");
  script_summary(english:"Checks the ASA CX version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote security device is missing a vendor-supplied security
patch.");
  script_set_attribute(attribute:"description", value:
"The remote ASA Next-Generation Firewall (NGFW) host is missing a
security patch. It is, therefore, affected by a certificate validation
bypass vulnerability in the bundled version of OpenSSL. The
vulnerability exists due to a flaw in the X509_verify_cert() function
in x509_vfy.c that is triggered when locating alternate certificate
chains when the first attempt to build such a chain fails. A remote
attacker can exploit this, by using a valid leaf certificate as a
certificate authority (CA), to issue invalid certificates that will
bypass authentication.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150710-openssl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91e2a837");
  script_set_attribute(attribute:"see_also", value:"https://openssl.org/news/secadv/20150709.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuv26213.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:adaptive_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA-CX/Version");
  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

ver = get_kb_item_or_exit('Host/Cisco/ASA-CX/Version');
fix = '9.3.4.2(11)';

# Versions 9.1.x, 9.2.x, and 9.3.x prior to 9.3.4.2 Build 11 are vulnerable
if (
  cisco_gen_ver_compare(a:ver, b:"9.1.0") >= 0 &&
  cisco_gen_ver_compare(a:ver, b:fix) < 0
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed release : ' + ver +
      '\n  Fixed release     : ' + fix +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'ASA CX/NGFW', ver);
