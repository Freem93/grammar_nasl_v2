#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87373);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/08 14:50:45 $");

  script_cve_id("CVE-2015-8339", "CVE-2015-8340");
  script_bugtraq_id(79038);
  script_osvdb_id(131284, 131285);

  script_name(english:"Citrix XenServer Multiple memory_exchange() Hypercall Error Handling DoS (CTX203451)");
  script_summary(english:"Checks for patches.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer running on the remote host is affected
by multiple denial of service vulnerabilities due to multiple flaws in
the memory_exchange() function in memory.c that are triggered when
handling hypercall XENMEM_exchange errors. A local attacker within a
guest can exploit these flaws to cause a deadlock, resulting in a
denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX203451");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant hotfix referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/12/08");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/15");

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
  fix = "XS60E054";
  if ("XS60E054" >!< patches) vuln = TRUE;
}
else if (version == "6.0.2")
{
  fix = "XS602E049 or XS602ECC025";
  if ("XS602E049" >!< patches && "XS602ECC025" >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.1\.")
{
  fix = "XS61E061";
  if ("XS61E061" >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.2\.")
{
  fix = "XS62ESP1035";
  if ("XS62ESP1035" >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.5\.")
{
  fix = "XS65ESP1019";
  if ("XS65ESP1019" >!< patches) vuln = TRUE;
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
