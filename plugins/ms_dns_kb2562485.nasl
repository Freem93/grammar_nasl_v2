#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72836);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/03/11 16:54:04 $");

  script_cve_id("CVE-2011-1966", "CVE-2011-1970");
  script_bugtraq_id(49012, 49019);
  script_osvdb_id(74399, 74400);
  script_xref(name:"MSFT", value:"MS11-058");

  script_name(english:"MS11-058: Vulnerabilities in DNS Server Could Allow Remote Code Execution (2562485) (uncredentialed check)");
  script_summary(english:"Checks version of Microsoft DNS Server");

  script_set_attribute(attribute:"synopsis", value:
"The DNS server running on the remote host has multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Microsoft DNS Server
running on the remote host has the following vulnerabilities :

  - A memory corruption vulnerability exists that can be
    triggered by an attacker sending a specially crafted
    NAPTR query. This could result in arbitrary code
    execution. (CVE-2011-1966)

  - A denial of service vulnerability exists related to the
    improper handling of uninitialized memory. This may
    result in the DNS service becoming unresponsive.
    (CVE-2011-1970)");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-058");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2003, 2008, and
2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("ms_dns_version.nasl");
  script_require_keys("ms_dns/version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("ms_dns/version");
port = 53;
fix = NULL;

# Windows Server 2008 R2
if (version =~ "^6\.1\.7601\.21\d{3}$" && ver_compare(ver:version, fix:"6.1.7601.21754") == -1)
  fix = "6.1.7601.21754";
else if (version =~ "^6\.1\.7601\.17\d{3}$" && ver_compare(ver:version, fix:"6.1.7601.17639") == -1)
  fix = "6.1.7601.17639";
else if (version =~ "^6\.1\.7600\.20\d{3}$" && ver_compare(ver:version, fix:"6.1.7600.20993") == -1)
  fix = "6.1.7600.20993";
else if (version =~ "^6\.1\.7600\.16\d{3}$" && ver_compare(ver:version, fix:"6.1.7600.16840") == -1)
  fix = "6.1.7600.16840";

# Windows 2008
else if (version =~ "^6\.0\.6002\.22\d{3}$" && ver_compare(ver:version, fix:"6.0.6002.22665") == -1)
  fix = "6.0.6002.22665";
else if (version =~ "^6\.0\.6002\.18\d{3}$" && ver_compare(ver:version, fix:"6.0.6002.18486") == -1)
  fix = "6.0.6002.18486";
else if ( get_kb_item("Settings/PCI_DSS") && version =~ "^6\.0\.6001\.18\d{3}$" )
  fix = "6.0.6002.18486";

# Windows 2003 SP2
else if (
  version =~ "^5\.2\.3790\." &&
  ver_compare(ver:version, fix:"5.2.3790.3959") >= 0 &&
  ver_compare(ver:version, fix:"5.2.3790.4882") == -1
)
    fix = "5.2.3790.4882";

else
  audit(AUDIT_LISTEN_NOT_VULN, "Microsoft DNS", port, version, "UDP");


if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_hole(port:port, proto:"udp", extra:report);
}
else security_hole(port:port, proto:"udp");
