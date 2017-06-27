#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85685);

  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id("CVE-2015-1793");
  script_bugtraq_id(75652);
  script_osvdb_id(124300);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150710-openssl");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv26137");

  script_name(english:"Cisco Virtual Security Gateway OpenSSL Alternative Certificate Validation Bypass (cisco-sa-20150710-openssl)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Virtual Security Gateway device is affected by a
certificate validation bypass vulnerability in the bundled OpenSSL
library due to a flaw in the X509_verify_cert() function in x509_vfy.c
that is triggered when locating alternate certificate chains in cases
where the first attempt to build such a chain fails. A remote attacker
can exploit this, by using a valid leaf certificate as a certificate
authority (CA), to issue invalid certificates that will bypass
authentication.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150710-openssl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91e2a837");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuv26137");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150709.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuv26137.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");

device = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");
version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

if ( device != "Nexus" ) audit(AUDIT_HOST_NOT, "affected");

if ( model !~ "^\d+VSG" ) audit(AUDIT_HOST_NOT, "affected");

# There is no way we can be sure this is a VSG on Hyper-V
if ( report_paranoia < 2 ) audit(AUDIT_PARANOID);

# From CRVF
if (version == "5.2(1)SM1(5.1)") flag++;

# From Bug Description
if (version == "5.2(1)VSG2(1.2)") flag++;
if (version == "5.2(1)VSG2(1.2a)") flag++;
if (version == "5.2(1)VSG2(1.2b)") flag++;
if (version == "5.2(1)VSG2(1.2c)") flag++;
if (version == "5.2(1)VSG2(1.3)") flag++;

# From Bug Affected List
if (version == "5.2(1)VSG2(1.1)") flag++;
if (version == "5.2(1)VSG2(1.1b)") flag++;

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCuv26137' +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.2(1)VSG2(1.4)' +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(port:0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
