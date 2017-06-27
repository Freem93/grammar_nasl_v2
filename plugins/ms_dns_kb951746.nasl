#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72834);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/13 15:25:35 $");

  script_cve_id("CVE-2008-1447", "CVE-2008-1454");
  script_bugtraq_id(30131, 30132);
  script_osvdb_id(46777, 46778);
  script_xref(name:"CERT", value:"800113");
  script_xref(name:"IAVA", value:"2008-A-0045");
  script_xref(name:"MSFT", value:"MS08-037");

  script_name(english:"MS08-037: Vulnerabilities in DNS Could Allow Spoofing (951746) (uncredentialed check)");
  script_summary(english:"Checks version of Microsoft DNS Server");

  script_set_attribute(attribute:"synopsis", value:
"The DNS server running on the remote host is vulnerable to DNS spoofing
attacks.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Microsoft DNS Server
running on the remote host contains issues in the DNS library that could
allow an attacker to send malicious DNS responses to DNS requests made
by the remote host thereby spoofing or redirecting internet traffic from
legitimate locations.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms08-037");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released patches for Windows 2000, 2003, and 2008
Server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2008/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
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


# Windows Server 2008
if (version =~ "^6\.0\.6001\.22\d{3}$" && ver_compare(ver:version, fix:"6.0.6001.22192") == -1)
  fix = "6.0.6001.22192";
else if (version =~ "^6\.0\.6001\.18\d{3}$" && ver_compare(ver:version, fix:"6.0.6001.18081") == -1)
  fix = "6.0.6001.18081";
# Windows Server 2003
else if (version =~ "^5\.2\.3790\.")
{
  # SP2
  if (
    ver_compare(ver:version, fix:"5.2.3790.3959") >= 0 &&
    ver_compare(ver:version, fix:"5.2.3790.4318") == -1
  )
    fix = "5.2.3790.4318";

  # SP1
  else if (ver_compare(ver:version, fix:"5.2.3790.3161") == -1)
    fix = "5.2.3790.3161";
  else
    audit(AUDIT_LISTEN_NOT_VULN, "Microsoft DNS Server", port, version, "UDP");
}
# Windows Server 2000
else if (version =~ "^5\.0\.2195\." && ver_compare(ver:version, fix:"5.0.2195.7162") == -1)
  fix = "5.0.2195.7162";
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
