#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87012);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/08 14:50:45 $");

  script_cve_id("CVE-2015-5307", "CVE-2015-8104");
  script_bugtraq_id(77524, 77528);
  script_osvdb_id(130089, 130090);

  script_name(english:"Citrix XenServer Multiple Infinite Loop Guest-to-Host DoS (CTX202583)");
  script_summary(english:"Checks for patches.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer running on the remote host is affected
by multiple denial of service vulnerabilities :

  - An infinite loop condition exists in the KVM subsystem
    that is triggered when handling a stream of #AC
    (Alignment Check) exceptions. A local attacker within a
    virtualized guest can exploit this to cause a host OS
    panic or hang, resulting in a denial of service
    condition. (CVE-2015-5307)

  - An infinite loop condition exists in the KVM subsystem
    that is triggered when handling a stream of #DB (Debug)
    exceptions. A local attacker within a virtualized guest
    can exploit this to cause a host OS panic or hang,
    resulting in a denial of service condition.
    (CVE-2015-8104)");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX202583");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant hotfix referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/11/09");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/23");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:xenserver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("citrix_xenserver_version.nbin");
  script_require_keys("Host/XenServer/version", "Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Citrix XenServer";
version = get_kb_item_or_exit("Host/XenServer/version");
get_kb_item_or_exit("Host/local_checks_enabled");
patches = get_kb_item("Host/XenServer/patches");
vuln = FALSE;
fix = '';

# We will do our checks within the branches since there can be SP releases
# special treatment.
if (version == "6.0.0")
{
  fix = "XS60E053";
  if ("XS60E053" >!< patches) vuln = TRUE;
}
else if (version == "6.0.2")
{
  fix = "XS602E048 or XS602ECC024";
  if ("XS602E048" >!< patches && "XS602ECC024" >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.1\.")
{
  fix = "XS61E060";
  if ("XS61E060" >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.2\.")
{
  fix = "XS62ESP1034";
  if ("XS62ESP1034" >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.5\.")
{
  fix = "XS65ESP1016 or XS65E017";
  if ("XS65ESP1016" >!< patches && "XS65E017" >!< patches) vuln = TRUE;
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

if (vuln)
{
  port = 0;
  report =
    '\n  Installed version : ' + version +
    '\n  Missing hotfix    : ' + fix +
    '\n';

  security_report_v4(severity:SECURITY_WARNING, extra:report, port:port);
}
else audit(AUDIT_PATCH_INSTALLED, fix);
