#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83763);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/02/08 14:50:45 $");

  script_cve_id("CVE-2015-3456");
  script_bugtraq_id(74640);
  script_osvdb_id(122072);

  script_name(english:"Citrix XenServer QEMU FDC Buffer Overflow RCE (CTX201078) (VENOM)");
  script_summary(english:"Checks for patches.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Citrix XenServer that is
affected by a flaw in the Floppy Disk Controller (FDC) in the bundled
QEMU software due to an overflow condition in hw/block/fdc.c when
handling certain commands. An attacker, with access to an account on
the guest operating system with privilege to access the FDC, can
exploit this flaw to execute arbitrary code in the context of the
hypervisor process on the host system.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX201078");
  script_set_attribute(attribute:"see_also", value:"http://venom.crowdstrike.com/");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant hotfix referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/05/13");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/21");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:xenserver");
  script_set_attribute(attribute:"in_the_news", value:"true");
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

# We will do our checks within the branches because 6.0.2 needs
# special treatment.
if (version == "6.0.0")
{
  fix = "XS60E047";
  if ("XS60E047" >!< patches) vuln = TRUE;
}
else if (version == "6.0.2")
{
  fix = "XS602E043 or XS602ECC019";
  if ("XS602E043" >!< patches && "XS602ECC019" >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.1\.")
{
  fix = "XS61E052";
  if ("XS61E052" >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.2\.")
{
  fix = "XS62ESP1025";
  if ("XS62ESP1025" >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.5\.")
{
  fix = "XS65ESP1002 or XS65E009";
  if ("XS65ESP1002" >!< patches && "XS65E009" >!< patches) vuln = TRUE;
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

if (vuln)
{
  port = 0;
  report =
    '\n  Installed version : ' + version +
    '\n  Missing hotfix    : ' + fix +
    '\n';

  security_report_v4(severity:SECURITY_HOLE, extra:report, port:port);
}
else audit(AUDIT_PATCH_INSTALLED, fix);
