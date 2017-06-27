#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70076);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/09/24 11:12:19 $");

  script_cve_id("CVE-2013-3382");
  script_bugtraq_id(60803);
  script_osvdb_id(94606);
  script_xref(name:"CISCO-BUG-ID", value:"CSCue88387");
  script_xref(name:"IAVA", value:"2013-A-0132");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130626-ngfw");

  script_name(english:"Cisco ASA Next-Generation Firewall Fragmented Traffic DoS (cisco-sa-20130626-ngfw)");
  script_summary(english:"Check ASA version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote security device is missing a vendor-supplied security
patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Cisco ASA NGFW host is missing a security patch.  It,
therefore, could be affected by an issue that if successfully exploited,
could result in a denial of service condition where the system reloads
and/or stops processing/inspecting traffic."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130626-ngfw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?501ffcc1");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130626-ngfw."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:adaptive_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");

  script_require_keys("Host/Cisco/ASA-CX/Version");
  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

ver = get_kb_item_or_exit('Host/Cisco/ASA-CX/Version');
# all versions of 9.0 are vulnerable
if (ver =~ '^9\\.0($|[^0-9])')
{
  report =
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : 9.1.1(9) or 9.1.2(12)' + '\n';
  security_hole(port:0, extra:report);
  exit(0);
}

# versions of 9.1.1 < 9.1.1.9 are vulnerable
if ( (cisco_gen_ver_compare(a:ver, b:"9.1.1") >= 0) && (cisco_gen_ver_compare(a:ver, b:"9.1.1(9)") < 0) )
{
  report =
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : 9.1.1(9)' + '\n';
  security_hole(port:0, extra:report);
  exit(0);
}

# versions of 9.1.2 < 9.1.2.12 are vulnerable
if ( (cisco_gen_ver_compare(a:ver, b:"9.1.2") >= 0) && (cisco_gen_ver_compare(a:ver, b:"9.1.2(12)") < 0) )
{
  report =
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : 9.1.2(12)' + '\n';
  security_hole(port:0, extra:report);
  exit(0);
}

audit(AUDIT_INST_VER_NOT_VULN, 'ASA CX/NGFW', ver);
