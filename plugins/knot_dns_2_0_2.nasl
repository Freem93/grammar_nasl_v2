#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87965);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:42:40 $");

  script_osvdb_id(132053);

  script_name(english:"Knot DNS 1.6.x < 1.6.6 / 2.0.x < 2.0.2 NAPTR Record DoS");
  script_summary(english:"Checks the version of Knot DNS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote DNS server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Knot DNS server running on the remote host is version 1.6.x prior
to 1.6.6 or 2.0.x prior to 2.0.2. It is, therefore, affected by an
out-of-bounds read error that occurs when parsing malformed NAPTR
records. An unauthenticated, remote attacker can exploit this to
disclose memory contents or crash the knotd daemon, resulting in a
denial of service.");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.labs.nic.cz/labs/knot/raw/v1.6.6/NEWS");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.labs.nic.cz/labs/knot/raw/v2.0.2/NEWS");
  # https://lists.nic.cz/pipermail/knot-dns-users/2015-November/000746.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc772026");
  # https://lists.nic.cz/pipermail/knot-dns-users/2015-November/000748.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9eb6eda3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Knot DNS version 1.6.6 / 2.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cz.nic:knot_dns");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

if (version =~ "^1(\.6)?$" || version =~ "^2(\.0)?$")
  audit(AUDIT_VER_NOT_GRANULAR, "Knot DNS", port, version);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (
  version =~ "^1\.6\.[0-5]($|[^0-9])" ||
  version =~ "^2\.0\.[0-1]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.6.6 / 2.0.2' +
      '\n';
    security_warning(port:port, proto:tolower(proto), extra:report);
  }
  else security_warning(port:port, proto:tolower(proto));
}
else audit(AUDIT_LISTEN_NOT_VULN, "Knot DNS", port, version, proto);
