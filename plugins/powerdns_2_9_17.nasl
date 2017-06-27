#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(87944);
 script_version("$Revision: 1.2 $");
 script_cvs_date("$Date: 2016/01/18 16:21:03 $");

 script_cve_id("CVE-2005-0038", "CVE-2005-0428");
 script_bugtraq_id(13729);
 script_osvdb_id(13466, 25291);

 script_name(english:"PowerDNS < 2.9.17 Multiple DoS");
 script_summary(english:"Checks the version of PowerDNS.");

 script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by multiple denial of service
vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of the
PowerDNS service listening on the remote host is prior to 2.9.17. It
is, therefore, affected by multiple denial of service
vulnerabilities : 

  - A denial of service vulnerability exists due to a flaw
  	that is triggered when the server receives a compressed
  	DNS packet with a label length byte with an incorrect
  	offset. A remote attacker can exploit this to trigger an
  	infinite loop, resulting in a denial of service
  	condition. (CVE-2005-0038)

  - An unspecified flaw exists in the DNSPacket::expand()
  	method in dnspacket.cc. A emote attacker can exploit
  	flaw, by sending a random stream of bytes, to cause a
  	denial of service condition. (CVE-2005-0428)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
 script_set_attribute(attribute:"see_also", value:"https://doc.powerdns.com/md/changelog/#version-2917");
 script_set_attribute(attribute:"solution", value:
"Upgrade to PowerDNS version 2.9.17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/02");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/05/02");
 script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/15");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:powerdns:powerdns");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
 script_family(english:"DNS");

 script_dependencie("pdns_version.nasl");
 script_require_keys("pdns/version", "pdns/version_full", "pdns/version_source", "Settings/ParanoidReport");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "PowerDNS";
version_source = get_kb_item_or_exit("pdns/version_source");
version_full = get_kb_item_or_exit("pdns/version_full");
version = get_kb_item_or_exit("pdns/version");

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_APP_VER, app_name);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = '2.9.17';
port = 53;

if (ver_compare(ver:version, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version_full, "UDP");

if (report_verbosity > 0)
{
  report =
    '\n  Version source    : ' + version_source +
    '\n  Installed version : ' + version_full +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_warning(port:port, proto:"udp", extra:report);
}
else security_warning(port:port, proto:"udp");
