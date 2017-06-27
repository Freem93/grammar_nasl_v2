#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87598);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/06/20 20:49:17 $");

  script_osvdb_id(
    120485,
    120486,
    120487
  );

  script_name(english:"Knot DNS < 1.6.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Knot DNS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote DNS server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Knot DNS prior to 1.6.3. It
is, therefore, affected by multiple vulnerabilities :

  - An out-of-bounds read error exists in the
    knot_rrset_rr_to_canonical() function. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted packet, to disclose sensitive
    information or cause a denial of service.
    (VulnDB 120485)

  - An out-of-bounds read error exists in the zone parser
    due to improper handling of origin domain names. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted zone, to disclose sensitive
    information or cause a denial of service.
    (VulnDB 120486)

  - An out-of-bounds read error exists in the rdata_seek()
    function. An unauthenticated, remote attacker can
    exploit this, via a specially crafted packet, to
    disclose sensitive information or cause a denial of
    service. (VulnDB 120487)");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.labs.nic.cz/labs/knot/raw/v1.6.3/NEWS");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Knot DNS version 1.6.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cz.nic:knot_dns");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("knot_dns_version.nasl");
  script_require_keys("knot_dns/proto", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

proto = get_kb_item("knot_dns/proto");

port = 53;
version = get_kb_item_or_exit("knot_dns/"+proto+"/version");
num_ver = get_kb_item_or_exit("knot_dns/"+proto+"/num_ver");

if (num_ver =~ "^1(\.6)?$") audit(AUDIT_VER_NOT_GRANULAR, "Knot DNS", port, version);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = "1.6.3";
if (ver_compare(ver:num_ver, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, proto:tolower(proto), extra:report);
  }
  else security_hole(port:port, proto:tolower(proto));
}
else audit(AUDIT_LISTEN_NOT_VULN, "Knot DNS", port, version, proto);
