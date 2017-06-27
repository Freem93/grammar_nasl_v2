#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72833);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/03/11 16:54:04 $");

  script_cve_id("CVE-2007-3898");
  script_bugtraq_id(25919);
  script_osvdb_id(41092);
  script_xref(name:"CERT", value:"484649");
  script_xref(name:"MSFT", value:"MS07-062");

  script_name(english:"MS07-062: Vulnerability in DNS Could Allow Spoofing (941672) (uncredentialed check)");
  script_summary(english:"Checks version of Microsoft DNS Server");

  script_set_attribute(attribute:"synopsis", value:
"The DNS server running on the remote host is vulnerable to DNS spoofing
attacks.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Microsoft DNS Server
running on the remote host contains an issue with the entropy of
transaction IDs that could allow an attacker to spoof DNS responses.  By
exploiting this issue, an attacker may be able to redirect legitimate
traffic from other systems that could allow him to construct more
complex attacks.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/MS07-062");
  script_set_attribute(attribute:"solution", value:"Microsoft has released patches for Windows 2000 and 2003 Server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/13");
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

# Windows Server 2003
if (version =~ "^5\.2\.3790\.")
{
  # SP2
  if (
    ver_compare(ver:version, fix:"5.2.3790.3959") >= 0 &&
    ver_compare(ver:version, fix:"5.2.3790.4171") == -1
  )
    fix = "5.2.3790.4171";

  # SP1
  else if (ver_compare(ver:version, fix:"5.2.3790.3027") == -1)
    fix = "5.2.3790.3027";
 else
    audit(AUDIT_LISTEN_NOT_VULN, "Microsoft DNS Server", port, version, "UDP");
}
# Windows 2000
else if (version =~ "^5\.0\.2195\." && ver_compare(ver:version, fix:"5.0.2195.7147") == -1)
  fix = "5.0.2195.7147";
else
  audit(AUDIT_LISTEN_NOT_VULN, "Microsoft DNS Server", port, version, "UDP");


if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_warning(port:port, proto:"udp", extra:report);
}
else security_warning(port:port, proto:"udp");
