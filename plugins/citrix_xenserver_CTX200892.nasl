#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83163);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/02/08 14:50:45 $");

  script_cve_id(
    "CVE-2014-3615",
    "CVE-2014-7815",
    "CVE-2014-8106"
  );
  script_bugtraq_id(69654, 70998, 71477);
  script_osvdb_id(111030, 113748, 115343, 115344 );

  script_name(english:"Citrix XenServer Multiple Vulnerabilities (CTX200892)");
  script_summary(english:"Checks the XenServer version and installed hotfixes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer installed on the remote host is
affected by multiple vulnerabilities :

  - A flaw exists in the VGA emulator in QEMU that allows a
    local guest user to read host memory by setting the
    display to a high resolution. (CVE-2014-3615)

  - A flaw exists in the set_pixel_format() function within
    ui/vnc.c in QEMU that allows a remote attacker, using
    a small bytes_per_pixel value, to cause a denial of
    service condition. (CVE-2014-7815)

  - A heap-based buffer overflow flaw exists in the Cirrus
    VGA emulator that allows local guest users to execute
    arbitrary code via vectors related to blit regions.
    (CVE-2014-8106)

Note that environments that contain only PV guests are not vulnerable
to these issues.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX200892");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant hotfix referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:xenserver");
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
  fix = "XS60E046";
  if ("XS60E046" >!< patches) vuln = TRUE;
}
else if (version == "6.0.2")
{
  fix = "XS602E042 or XS602ECC018 ";
  if ("XS602E042" >!< patches && "XS602ECC018" >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.1\.")
{
  fix = "XS61E051";
  if ("XS61E051" >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.2\.")
{
  fix = "XS62ESP1021";
  if ("XS62ESP1021" >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.5\.")
{
  fix = "XS65E007";
  if ("XS65E007" >!< patches) vuln = TRUE;
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
