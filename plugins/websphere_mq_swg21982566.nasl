#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93049);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_cve_id(
    "CVE-2016-0264",
    "CVE-2016-3426",
    "CVE-2016-3427"
  );
  script_bugtraq_id(
    86421,
    86449
  );
  script_osvdb_id(
    137303,
    137308,
    137755
  );

  script_name(english:"IBM WebSphere MQ 7.1 < 7.1.0.8 / 7.5 < 7.5.0.7 / 8.0 < 8.0.0.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of IBM WebSphere MQ.");

  script_set_attribute(attribute:"synopsis", value:
"A message queuing service installed on the remote host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM WebSphere MQ server
installed on the remote Windows host is version 7.1 without fix pack
7.1.0.8, 7.5 without fix pack 7.5.0.7, or 8.0 without fix pack
8.0.0.5. It is, therefore, affected by multiple vulnerabilities :

  - A buffer overflow condition exists in IBM JVM due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code under limited circumstances.
    (CVE-2016-0264)

  - An unspecified flaw exists in the JCE subcomponent that
    allows an unauthenticated, remote attacker to disclose
    potentially sensitive information. (CVE-2016-3426)

  - An unspecified flaw exists in the JMX subcomponent that
    allows an unauthenticated, remote attacker to impact
    confidentiality, integrity, and availability. No other
    details are available. (CVE-2016-3427)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21982566");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate fix pack according to the vendor advisory.
Alternatively, interim fix IT14908 can also be applied to mitigate
these vulnerabilities if a fix pack is not available.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("websphere_mq_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere MQ", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "IBM WebSphere MQ";
install  = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
if (report_paranoia < 2) audit(AUDIT_PARANOID);
version  = install['version'];
path     = install['path'];
type     = install['Type'];
fix      = FALSE;
fixes    = make_array(
  "^7\.1\.0\.", "7.1.0.8",
  "^7\.5\.0\.", "7.5.0.7",
  "^8\.0\.0\.", "8.0.0.5"
);

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
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
