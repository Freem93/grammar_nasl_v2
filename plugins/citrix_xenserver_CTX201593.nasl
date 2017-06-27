#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85242);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/02/08 14:50:45 $");

  script_cve_id("CVE-2015-5154");
  script_bugtraq_id(76048);
  script_osvdb_id(125389);

  script_name(english:"Citrix XenServer QEMU IDE Buffer Overflow Code Execution (CTX201593)");
  script_summary(english:"Checks for patches.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer running on the remote host is affected
by a heap buffer overflow condition in the IDE subsystem of the
bundled QEMU software, which is related to I/O buffer access when
handling certain ATAPI commands. An attacker, with sufficient
privileges in an HVM guest VM, can exploit this issue to execute
arbitrary code in the context of the hypervisor process on the host
system. Note that exploitation requires the CDROM drive to be enabled
on the guest system.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX201593");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant hotfix referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/07/27");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/05");

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

# We will do our checks within the branches because 6.0.2 needs
# special treatment.
if (version == "6.0.0")
{
  fix = "XS60E050";
  if ("XS60E050" >!< patches) vuln = TRUE;
}
else if (version == "6.0.2")
{
  fix = "XS602E045 or XS602ECC021";
  if ("XS602E045" >!< patches && "XS602ECC021" >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.1\.")
{
  fix = "XS61E057";
  if ("XS61E057" >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.2\.")
{
  fix = "XS62ESP1030";
  if ("XS62ESP1030" >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.5\.")
{
  fix = "XS65ESP1008 or XS65E013";
  if ("XS65ESP1008" >!< patches && "XS65E013" >!< patches) vuln = TRUE;
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
