#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69135);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/01/26 03:37:38 $");

  script_cve_id("CVE-2012-5424");
  script_bugtraq_id(56433);
  script_osvdb_id(87251);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuc65634");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20121107-acs");

  script_name(english:"Cisco Secure Access Control System TACACS+ Authentication Bypass (cisco-sa-20121107-acs)");
  script_summary(english:"Checks ACS version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Cisco Secure Access Control (ACS) running on the remote
host has an authentication bypass vulnerability.  When the system is
configured with an LDAP external identity store and TACACS+ is the
authentication protocol, the user-supplied password is not properly
validated.  A remote attacker could exploit this to authenticate as a
known user to any system using TACACS+ in conjunction with an affected
Cisco Secure ACS."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20121107-acs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db07b48f");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to the relevant Cisco Secure Access Control System version
referenced in Cisco Security Advisory cisco-sa-20121107-acs."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:secure_acs");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("cisco_secure_acs_version.nasl");
  script_require_keys("Host/Cisco/ACS/Version", "Host/Cisco/ACS/DisplayVersion");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/ACS/Version");
display_ver = get_kb_item_or_exit("Host/Cisco/ACS/DisplayVersion");

if (ver =~ "^5\.[01]\.")
  fix = 'Migrate to 5.2 Patch 11 (5.2.0.26.11)';
else if (ver =~ "^5\.2\.")
  fix = '5.2.0.26.11';
else if (ver =~ "^5\.3\.")
  fix = '5.3.0.40.7';
else
  fix = NULL; # the software is no vulnerable, no fix is needed

if (
  isnull(fix) ||
  ('Migrate' >!< fix && ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
)
{
  audit(AUDIT_INST_VER_NOT_VULN, 'Secure ACS', display_ver);
}

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + display_ver +
    '\n  Fixed version     : ' + fix + '\n';
  security_warning(port:0, extra:report);
}
else security_warning(0);

