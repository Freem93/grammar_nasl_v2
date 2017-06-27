#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79218);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/24 13:12:21 $");

  script_cve_id("CVE-2014-3566");
  script_bugtraq_id(70574);
  script_osvdb_id(113251);
  script_xref(name:"CERT", value:"577193");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur23720");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur38423");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20141015-poodle");

  script_name(english:"Cisco Unified Communications Manager SSLv3 Information Disclosure (cisco-sa-20141015-poodle) (POODLE)");
  script_summary(english:"Checks the version of Cisco Unified Communications Manager (CUCM).");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a man-in-the-middle (MitM)
information disclosure vulnerability known as POODLE.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Cisco Unified
Communications Manager (CUCM) device is affected by a
man-in-the-middle (MitM) information disclosure vulnerability known as
POODLE. The vulnerability is due to the way SSL 3.0 handles padding
bytes when decrypting messages encrypted using block ciphers in cipher
block chaining (CBC) mode. A MitM attacker can decrypt a selected byte
of a cipher text in as few as 256 tries if they are able to force a
victim application to repeatedly send the same data over newly created
SSL 3.0 connections.");

  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20141015-poodle
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7453d3be");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");

  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in the Cisco bug advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:TF/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver         = get_kb_item_or_exit("Host/Cisco/CUCM/Version");
ver_display = get_kb_item_or_exit("Host/Cisco/CUCM/Version_Display");

app_name  = "Cisco Unified Communications Manager (CUCM)";
fixed_ver = "10.5.1.98000-180";

if (
  ver =~ "^7\.1\.5\."  ||
  ver =~ "^8\.5\.1\."  ||
  ver =~ "^8\.6\.2\."  ||
  ver =~ "^9\.1\.2\."  ||
  ver =~ "^10\.0\.1\." ||
  (ver =~ "^10\.5\.1\." && ver_compare(ver:ver, fix:"10.5.1.98000.180", strict:FALSE) < 0)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCur23720 / CSCur38423'  +
      '\n  Installed release : ' + ver_display +
      '\n  Fixed release     : ' + fixed_ver   +
      '\n';

    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, app_name, ver_display);
