#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(87593);
 script_version("$Revision: 1.1 $");
 script_cvs_date("$Date: 2015/12/22 19:11:16 $");

 script_osvdb_id(122461);

 script_name(english:"dnsmasq 2.73rc6 < 2.73rc8 extract_name() Function RCE");
 script_summary(english:"Checks the version of dnsmasq.");

 script_set_attribute(attribute:"synopsis", value:
"The remote DNS / DHCP service is affected by a remote code execution
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote dnsmasq server is running version 2.73rc6 or 2.73rc7. It
is, therefore, affected by a remote code execution vulnerability due
to an overflow condition in the extract_name() function in rfc1035.c
that occurs due to improper validation of user-supplied input. An
unauthenticated, remote attacker can exploit this to cause a denial of
service or the execution of arbitrary code.");
 # http://thekelleys.org.uk/gitweb/?p=dnsmasq.git;a=commit;h=5d07d77e75e0f02bc0a8f6029ffbc8b371fa804e
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d8b0a30e");
 script_set_attribute(attribute:"see_also", value:"http://www.thekelleys.org.uk/dnsmasq/CHANGELOG");
 script_set_attribute(attribute:"solution", value:
"Upgrade to dnsmasq 2.73rc8 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/15");
 script_set_attribute(attribute:"patch_publication_date", value:"2015/05/15");
 script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:thekelleys:dnsmasq");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
 script_family(english:"DNS");

 script_dependencie("dns_version.nasl");
 script_require_keys("dns_server/version", "Settings/ParanoidReport");
 script_require_ports("Services/dns", 53);

 exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");

app_name = "dnsmasq";

port = get_kb_item("Services/udp/dns");
if (!port) port = 53;

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = get_kb_item_or_exit("dns_server/version");
version = tolower(version);

if (version !~ "dnsmasq-(v)?")
	audit(AUDIT_NOT_LISTEN, app_name, port);

if (version =~ "^dnsmasq-(v)?(2\.73rc[6-7]$)")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : dnsmasq-2.73rc8' +
      '\n';

    security_hole(port:port, proto:"udp", extra:report);
  }
  else security_hole(port:port, proto:"udp");
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
