#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63099);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/06 17:22:03 $");

  script_cve_id("CVE-2012-2191", "CVE-2012-2203", "CVE-2012-4863");
  script_bugtraq_id(54743, 56471);
  script_osvdb_id(84473, 84474);

  script_name(english:"IBM WebSphere MQ 7.1 / 7.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of IBM WebSphere MQ.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a service installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere MQ server is version 7.1 without Fix 
Pack 7.1.0.2 or 7.5 without Fix Pack 7.5.0.1. It is, therefore, 
affected by the following vulnerabilities :

  - A flaw exists in Global Security Kit (GSkit) due to a
    failure to properly validate data when the 'protection
    mechanism' is executed against an SSL CBC timing attack.
    A remote attacker, using crafted values in the TLS Record
    Layer, can exploit this to cause a denial of service.
    (CVE-2012-2191)

  - A flaw exists in Global Security Kit (GSkit) due to a
    failure to properly verify certificates, which can allow
    a remote attacker to conduct a man-in-the-middle attack.
    (CVE-2012-2203)

  - An application can potentially put a sequence of large
    messages into the queue, causing a buffer to overflow in
    the queue manager. This can lead to a denial of service.
    (CVE-2012-4863)");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21614483");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21617837");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/websphere_mq_security_bulletin_multiple_vulnerabilities_in_gskit_component7?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be2ba65d");
  script_set_attribute(attribute:"solution", value:"Apply fix pack 7.1.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("websphere_mq_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere MQ");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "IBM WebSphere MQ";
install  = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version  = install['version'];
path     = install['path'];
type     = install['Type'];
fix      = FALSE;
fixes    = make_array(
  "^7\.1\.", "7.1.0.2",
  "^7\.5\.", "7.5.0.1"
);

# Only server
if (tolower(type) != "server")
  audit(AUDIT_HOST_NOT,app_name+" Server");

# Find the fix for our version
foreach fixcheck (keys(fixes))
{
  if(version =~ fixcheck)
  {
    fix = fixes[fixcheck];
    break;
  }
}

# Version not affected
if(!fix)
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

# Check affected version
if(ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
