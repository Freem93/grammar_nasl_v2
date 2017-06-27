#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 6000 ) exit(0);

include("compat.inc");

if (description)
{
  script_id(96663);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/03/03 21:32:20 $");

  script_cve_id(
    "CVE-2016-0360",
    "CVE-2016-3013",
    "CVE-2016-3052",
    "CVE-2016-8915",
    "CVE-2016-8971",
    "CVE-2016-8986",
    "CVE-2016-9009"
  );
  script_bugtraq_id(
    95317,
    96394,
    96400,
    96403,
    96412,
    96441
  );
  script_osvdb_id(
    149754,
    151616,
    151617,
    151618,
    151619,
    151620,
    151621
  );
  script_xref(name:"IAVA", value:"2017-A-0014");

  script_name(english:"IBM WebSphere MQ 7.0.1.x / 7.1.0.x < 7.1.0.9 / 7.5.0.x < 7.5.0.8 / 8.0.0.x < 8.0.0.6 / 9.0.0.x < 9.0.0.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of IBM WebSphere MQ.");

  script_set_attribute(attribute:"synopsis", value:
"A message queuing service installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM WebSphere MQ server
installed on the remote Windows host is version 7.0.1.x without patch
APAR IT14385, 7.1.0.x prior to 7.1.0.9, 7.5.0.x prior to 7.5.0.8,
8.0.0.x prior to 8.0.0.6, or 9.0.0.x prior to 9.0.0.1. It is,
therefore, affected by multiple vulnerabilities :

  - A flaw exists in the Java Message Service (JMS) in the
    JMSObjectMessage class due to improper sanitization of
    input when deserializing Java objects. An authenticated,
    remote attacker can exploit this to execute arbitrary
    code. (CVE-2016-0360)

  - A flaw exists due to improper data conversion handling
    that allows an authenticated, remote attacker to crash
    the MQ channel. (CVE-2016-3013)

  - A flaw exists that under nonstandard configurations
    causes password data to be sent in cleartext over the
    network. A man-in-the-middle attacker can exploit this
    to disclose passwords. (CVE-2016-3052)

  - An unspecified flaw exists that allows an authenticated,
    remote attacker, who has access to the queue manager and
    queue, to cause a denial of service to other channels
    running under the same process. (CVE-2016-8915)

  - A flaw exists that allows an unauthenticated, remote
    attacker to have an unspecified impact. No other details
    are available. (CVE-2016-8971)

  - An unspecified flaw exists that allows an authenticated,
    remote attacker, who has access to the queue manager,
    to disrupt MQ channels using specially crafted HTTP
    requests, resulting in a denial of service condition.
    (CVE-2016-8986)

  - An unspecified flaw exists that allows an authenticated,
    remote attacker, who has authority to create cluster
    objects, to cause a denial of service condition in
    MQ clustering. (CVE-2016-9009)");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg21983457");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg1SE66318");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate fix pack, APAR patch, or mitigation :

  - For versions 7.0.1.x, apply the patch APAR IT14385 and
    follow the instructions in the patch readme to apply
    serialization whitelisting.

  - For versions 7.1.0.x, apply fix pack 9 (7.1.0.9) when
    available. In the interim, apply the patch APAR IT14385
    and follow the instructions in the patch readme to apply
    serialization whitelisting.

  - For versions 7.5.0.x, apply fix pack 8 (7.5.0.8) when
    available. In the interim, apply the patch APAR IT14385
    and follow the instructions in the patch readme to apply
    serialization whitelisting.

  - For versions 8.0.0.x, apply fix pack 6 (8.0.0.6) when
    available. In the interim, use JSON or XML rather than
    ObjectMessage and enable MQ's Advanced Message Security
    (AMS) mechanism.

  - For versions 9.0.0.x, apply fix pack 1 (9.0.0.1) when
    available. In the interim, apply the patch APAR IT14385
    and follow the instructions in the patch readme to apply
    serialization whitelisting.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("websphere_mq_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere MQ", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("bsal.inc");
include("byte_func.inc");
include("zip.inc");

app_name = "IBM WebSphere MQ";
install  = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
if (report_paranoia < 2) audit(AUDIT_PARANOID);
version  = install['version'];
path     = install['path'];
type     = install['Type'];
fix      = FALSE;
flag    = FALSE;

switch[=~] (version)
{
  case "^7\.0\.1\.":
    contents = hotfix_get_file_contents(path + "\java\lib\com.ibm.mqjms.jar");
    prop = zip_parse(blob:contents['data'], 'com/ibm/msg/client/commonservices/resources/JMSCS_MessageResourceBundle.properties');
    if ("IT14385" >!< prop)
    {
      fix = "7.0.1.14 & IT14385";
      flag = TRUE;
    }
    break;
  case "^7\.1\.0\.":
    fix = "7.1.0.9";
    break;
  case "^7\.5\.0\.":
    fix = "7.5.0.8";
    break;
  case "^8\.0\.0\.":
    fix = "8.0.0.6";
    break;
  case "^9\.0\.0\.":
    fix = "9.0.0.1";
    break;
  default:
    audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
}


# Check affected version
if(flag || ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
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
