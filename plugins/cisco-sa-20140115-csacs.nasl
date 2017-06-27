#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71995);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id("CVE-2014-0648", "CVE-2014-0649",  "CVE-2014-0650");
  script_bugtraq_id(64958, 64962, 64964);
  script_osvdb_id(102115, 102116, 102117);
  script_xref(name:"CISCO-BUG-ID", value:"CSCud75180");
  script_xref(name:"CISCO-BUG-ID", value:"CSCud75187");
  script_xref(name:"CISCO-BUG-ID", value:"CSCue65962");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140115-csacs");

  script_name(english:"Multiple Vulnerabilities in Cisco Secure Access Control System (cisco-sa-20140115-csacs)");
  script_summary(english:"Checks the ACS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Cisco Secure Access Control System (ACS) running on the
remote host is affected by one or more of the following issues :

  - A flaw in the authorization enforcement of the RMI
    interface could allow a remote, authenticated attacker
    to perform actions as superadmin. (CVE-2014-0649)

  - A flaw in the authentication and authorization
    enforcement of the RMI interface could allow a remote,
    unauthenticated attacker to access the ACS via the RMI
    interface and perform administrative actions.
    (CVE-2014-0648)

  - A flaw in the input validation of the web interface
    could allow a remote, authenticated attacker to inject
    operating system-level commands, thus performing
    operating system-level commands without shell access.
    (CVE-2014-0650)"
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140115-csacs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a3eb5a2f");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=32378");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=32379");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=32380");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to the relevant Cisco Secure Access Control System version
referenced in Cisco Security Advisory cisco-sa-20140115-csacs."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:secure_acs");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_secure_acs_version.nasl");
  script_require_keys("Host/Cisco/ACS/Version", "Host/Cisco/ACS/DisplayVersion");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/ACS/Version");
display_ver = get_kb_item_or_exit("Host/Cisco/ACS/DisplayVersion");

if (ver =~ "^5\.")
  fix = '5.5';
else
  fix = NULL; # the software is not vulnerable, no fix is needed

if ( ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0 )
  audit(AUDIT_INST_VER_NOT_VULN, 'Secure ACS', display_ver);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + display_ver +
    '\n  Fixed version     : ' + fix + '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
