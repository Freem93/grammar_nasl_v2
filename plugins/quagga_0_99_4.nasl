#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59793);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_cve_id("CVE-2006-2223", "CVE-2006-2224", "CVE-2006-2276");
  script_bugtraq_id(17808, 17979);
  script_osvdb_id(25224, 25225, 25245);

  script_name(english:"Quagga < 0.98.6 / 0.99.4 Multiple Vulnerabilities");
  script_summary(english:"Check the version of Quagga");

  script_set_attribute(attribute:"synopsis", value:
"The remote service may be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Quagga listening on the remote host is affected by multiple
vulnerabilities :

  - An information disclosure vulnerability in RIPD can be
    triggered by a REQUEST packet, such as SEND UPDATE, on
    hosts that disable RIPv1 or require plaintext or MD5
    authentication. (CVE-2006-2223)

  - An authentication bypass vulnerability in RIPD may allow
    unauthenticated, remote attackers to modify routing
    state via RIPv1 RESPONSE packets. (CVE-2006-2224)

  - A denial of service vulnerability in Zebra can be
    triggered by a certain BGP command. (CVE-2006-2276)");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 0.98.6 / 0.99.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"see_also", value:"http://bugzilla.quagga.net/show_bug.cgi?id=261");
  script_set_attribute(attribute:"see_also", value:"http://bugzilla.quagga.net/show_bug.cgi?id=262");
  script_set_attribute(attribute:"see_also", value:"http://www.quagga.net/download/attic/quagga-0.99.4.changelog.txt");
  script_set_attribute(attribute:"see_also", value:"http://lists.quagga.net/pipermail/quagga-dev/2006-March/004052.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2006/May/32");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/30");
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

if (version =~ "^0\.98([^0-9]|$)")
  fix = "0.98.6";
else
  fix = "0.99.4";

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

security_warning(port:port, extra:report);
