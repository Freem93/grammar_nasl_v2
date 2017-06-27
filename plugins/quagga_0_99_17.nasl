#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59788);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_name(english:"Quagga < 0.99.17 BGPD Multiple Vulnerabilities");
  script_summary(english:"Check the version of Quagga");

  script_cve_id("CVE-2010-2948", "CVE-2010-2949");
  script_bugtraq_id(42635, 42642);
  script_osvdb_id(67394, 67404);

  script_set_attribute(attribute:"synopsis", value:
"The remote service may be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Quagga's BGPD listening on the remote host is affected by multiple
vulnerabilities :

  - A stack-based buffer overflow vulnerability can be
    triggered by a specially crafted BGP ROUTE-REFRESH
    message with a malformed Outbound Route Filtering record
    sent by a pre-configured peer. (CVE-2010-2948)

  - A denial of service vulnerability in BGPD can be
    triggered by a specially crafted UPDATE message with an
    unknown AS type in an AS path attribute.
    (CVE-2012-0250)");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 0.99.17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"see_also", value:"http://savannah.nongnu.org/forum/forum.php?forum_id=7140");
  script_set_attribute(attribute:"see_also", value:"http://www.quagga.net/download/quagga-0.99.17.changelog.txt");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/19");
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

fix = "0.99.17";
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

security_hole(port:port, extra:report);
