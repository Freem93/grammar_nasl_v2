#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76127);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/04 18:02:12 $");

  script_cve_id("CVE-2014-0224");
  script_bugtraq_id(67899);
  script_osvdb_id(107729);
  script_xref(name:"CERT", value:"978508");

  script_name(english:"Cisco ACE30 and ACE4710 OpenSSL 'ChangeCipherSpec' MiTM Vulnerability");
  script_summary(english:"Checks device version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a man-in-the-middle vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote device is running a software version known to be affected
by an OpenSSL related vulnerability. The flaw could allow a MiTM
attacker to decrypt or forge SSL messages by telling the service to
begin encrypted communications before key material has been exchanged,
which causes predictable keys to be used to secure future traffic.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140605-openssl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5539aa9d");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:"There is currently no known solution.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_control_engine_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ace_version.nasl");
  script_require_keys("Host/Cisco/ACE/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");

version = get_kb_item("Host/Cisco/ACE/Version");
if (isnull(version)) audit(AUDIT_NOT_INST, 'Cisco ACE');

if (
  version =~ "^A4\(([01]\..+|2\.[0-3][^\d]*)\)" ||
  version =~ "^A5\(([012]\..+|3\.0[^\d]*)\)"
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ACE", version);
