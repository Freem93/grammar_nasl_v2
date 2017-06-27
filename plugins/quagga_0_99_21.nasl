#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59792);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_cve_id("CVE-2012-1820");
  script_bugtraq_id(53775);
  script_osvdb_id(82692);
  script_xref(name:"CERT", value:"962587");

  script_name(english:"Quagga < 0.99.21 BGP Denial of Service Vulnerability");
  script_summary(english:"Check the version of Quagga");

  script_set_attribute(attribute:"synopsis", value:
"The remote service may be affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Quagga's BGP daemon listening on the remote host is affected by a
denial of service vulnerability. Unauthenticated attackers on the
local network can trigger this issue by leveraging a BGP peering
relationship and sending a malformed Outbound Route Filtering
capability TLV in an OPEN message.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 0.99.21 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"see_also", value:"http://savannah.nongnu.org/forum/forum.php?forum_id=7214");
  script_set_attribute(attribute:"see_also", value:"http://www.quagga.net/download/quagga-0.99.21.changelog.txt");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:quagga:quagga");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("quagga_zebra_detect.nasl");
  script_require_keys("Quagga/Installed", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "Quagga Zebra";
kb = "Quagga/";

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

port = get_kb_item_or_exit(kb + "Installed");

kb += port + "/";
banner = get_kb_item_or_exit(kb + "Banner");
ver = get_kb_item_or_exit(kb + "Version");

if (ver !~ "^\d+(\.\d+)*$")
  audit(AUDIT_NONNUMERIC_VER, app, port, ver);

fix = "0.99.21";
if (ver_compare(ver:ver, fix:fix, strict:TRUE) >= 0)
  audit(AUDIT_LISTEN_NOT_VULN, app, port, ver);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  Version source    : ' + banner +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
}

security_note(port:port, extra:report);
