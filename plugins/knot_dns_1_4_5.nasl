#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76799);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/11/06 15:17:46 $");

  script_bugtraq_id(67187);
  script_osvdb_id(105977);

  script_name(english:"Knot DNS < 1.4.5 TSIG Signature Spoofing");
  script_summary(english:"Checks the version of Knot DNS.");

  script_set_attribute(attribute:"synopsis", value:"The remote DNS server is potentially affected by a spoofing attack.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Knot DNS prior to 1.4.5. It
is, therefore, affected by an unspecified vulnerability in the TSIG
validation code that may allow spoofing attacks due to improper TSIG
signature verification.");
  script_set_attribute(attribute:"see_also", value:"http://freecode.com/projects/knot-dns/releases/363022");
  script_set_attribute(attribute:"solution", value:"Update to version 1.4.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cz.nic:knot_dns");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("knot_dns_version.nasl");
  script_require_keys("knot_dns/proto", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# May fork
proto = get_kb_item("knot_dns/proto");

port = 53;
version = get_kb_item_or_exit("knot_dns/"+proto+"/version");
num_ver = get_kb_item_or_exit("knot_dns/"+proto+"/num_ver");

if (version =~ "^1(\.4)?$") audit(AUDIT_VER_NOT_GRANULAR, "Knot DNS", port, version);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = "1.4.5";

if (
  version =~ "^0\." ||
  version =~ "^1\.[0-3]($|[^0-9])" ||
  version =~ "^1\.4\.[0-4]($|[^0-9])" ||
  version =~ "^1\.4\.5-rc\d"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, proto:tolower(proto), extra:report);
  }
  else security_warning(port:port, proto:tolower(proto));
}
else audit(AUDIT_LISTEN_NOT_VULN, "Knot DNS", port, version, proto);
