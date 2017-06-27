#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72837);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/12/12 18:38:05 $");

  script_cve_id("CVE-2012-0006");
  script_bugtraq_id(52374);
  script_osvdb_id(80005);
  script_xref(name:"MSFT", value:"MS12-017");

  script_name(english:"MS12-017: Vulnerability in DNS Server Could Allow Denial of Service (2647170) (uncredentialed check)");
  script_summary(english:"Checks version of Microsoft DNS Server");

  script_set_attribute(attribute:"synopsis", value:
"The DNS server running on the remote host is susceptible to a denial of
service attack.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Microsoft DNS server
running on the remote host does not properly handle objects in memory
when looking up the resource record of a domain.  By sending a specially
crafted DNS query an attacker may be able to exploit this flaw and cause
the DNS server on the remote host to stop responding and eventually
restart.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-017");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2003, 2008, and
2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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
if (version =~ "^6\.1\.7601\.21\d{3}$" && ver_compare(ver:version, fix:"6.1.7601.21885") == -1)
  fix = "6.1.7601.21885";
else if (version =~ "^6\.1\.7601\.17\d{3}$" && ver_compare(ver:version, fix:"6.1.7601.17750") == -1)
  fix = "6.1.7601.17750";
else if (version =~ "^6\.1\.7600\.20\d{3}$" && ver_compare(ver:version, fix:"6.1.7600.21114") == -1)
  fix = "6.1.7600.21114";
else if (version =~ "^6\.1\.7600\.16\d{3}$" && ver_compare(ver:version, fix:"6.1.7600.16936") == -1)
  fix = "6.1.7600.16936";

# Windows 2008 SP2
else if (version =~ "^6\.0\.6002\.22\d{3}$" && ver_compare(ver:version, fix:"6.0.6002.22763") == -1)
  fix = "6.0.6002.22763";
else if (version =~ "^6\.0\.6002\.18\d{3}$" && ver_compare(ver:version, fix:"6.0.6002.18557") == -1)
  fix = "6.0.6002.18557";
else if ( get_kb_item("Settings/PCI_DSS") && version =~ "^6\.0\.6001\.18\d{3}$" )
  fix = "6.0.6002.18557";

# Windows 2003 SP2
else if (
  version =~ "^5\.2\.3790\." &&
  ver_compare(ver:version, fix:"5.2.3790.3959") >= 0 &&
  ver_compare(ver:version, fix:"5.2.3790.4957") == -1
)
    fix = "5.2.3790.4957";

else
  audit(AUDIT_LISTEN_NOT_VULN, "Microsoft DNS", port, version, "UDP");


if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_warning(port:port, proto:"udp", extra:report);
}
else security_warning(port:port, proto:"udp");
