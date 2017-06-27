#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66861);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/01/10 05:42:14 $");

  script_cve_id("CVE-2013-1170");
  script_bugtraq_id(59013);
  script_osvdb_id(92216);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtz30468");
  script_xref(name:"CISCO-BUG-ID", value:"CSCub54624");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130410-ncs");

  script_name(english:"Cisco Prime Network Control System Default Credentials (cisco-sa-20130410-ncs)");
  script_summary(english:"Checks NCS version");

  script_set_attribute(
    attribute:"synopsis",
    value:"One or more accounts on the remote host use a default password."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the remote host is running a
release of Cisco Prime Network Control System prior to 1.1.2.  As
such, it reportedly has the following vulnerabilities :

  - The 'oracle' user account is secured with an unspecified,
    default password. (CSCtz30468)

  - The 'wcsdba' Oracle database account is secured with a
    default password of 'wcs123'. (CSCub54624)

A remote, unauthenticated attacker could exploit this to log into the
system and change its configuration or disrupt services."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130410-ncs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?544c200c");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Cisco Prime Network Control System version 1.1.2 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_network_control_system");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_prime_ncs_version.nasl");
  script_require_keys("Host/Cisco/Prime_NCS/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/Prime_NCS/Version");
fix = '1.1.2';
if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Prime NCS', ver);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix + '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
