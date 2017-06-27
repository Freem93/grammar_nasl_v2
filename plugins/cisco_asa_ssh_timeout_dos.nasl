#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64555);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/02/12 11:49:04 $");

  script_cve_id("CVE-2012-5717");
  script_bugtraq_id(57485);
  script_osvdb_id(89562);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtc59462");

  script_name(english:"Cisco ASA 5500 Series SSH Timeout DoS");
  script_summary(english:"Checks ASA model and version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote security device is missing a vendor-supplied security
patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Cisco ASA is missing a security patch and may be affected by
a denial of service vulnerability.  Due to a flaw in the management of
remote SSH sessions, multiple login sessions can cause the ASA to crash. 
A remote, authenticated attacker could exploit this to cause a denial of
service."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2012-5717
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b391dbe8");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Cisco ASA Software 8.4(1) / 8.5(1) / 8.6 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("cisco_func.inc");
include("audit.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');
ver = extract_asa_version(asa);
if (isnull(ver)) exit(1, 'Unable to parse ASA version.');

if (model !~ '^55[0-9][0-9]')
  audit(AUDIT_HOST_NOT, 'ASA 5500');

if (
  ver =~ "^8\.0[^0-9]" ||
  ver =~ "^8\.1[^0-9]" ||
  ver =~ "^8\.2[^0-9]" ||
  ver =~ "^8\.3[^0-9]"
)
{
  report =
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : 8.4(1) / 8.5(1) / 8.6\n';
  security_warning(port:0, extra:report);
}
else exit(0, "The remote host is running Cisco ASA release "+ver+" and is not affected.");

