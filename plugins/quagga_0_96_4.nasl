#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59786);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_cve_id("CVE-2003-0795");
  script_bugtraq_id(9029);
  script_osvdb_id(11747);

  script_name(english:"Quagga < 0.96.4 Zebra Denial of Service Vulnerability");
  script_summary(english:"Check the version of Quagga");

  script_set_attribute(attribute:"synopsis", value:
"The remote service may be affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Quagga's Zebra daemon listening on the remote host is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 0.96.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Nov/169");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=106883387304266&w=2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/11/12");
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

fix = "0.96.4";
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
