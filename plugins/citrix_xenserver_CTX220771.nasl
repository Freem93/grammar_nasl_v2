#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97525);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/03/24 14:10:48 $");

  script_cve_id(
    "CVE-2017-2615",
    "CVE-2017-2620"
  );
  script_bugtraq_id(
    95990,
    96378
  );
  script_osvdb_id(
    151241,
    152349
  );
  script_xref(name:"IAVB", value:"2017-B-0024");

  script_name(english:"Citrix XenServer Multiple Vulnerabilities (CTX220771)");
  script_summary(english:"Checks for patches.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer running on the remote host is missing
a security hotfix. It is, therefore, affected by the following
vulnerabilities :

  - A flaw exists in the blit_region_is_unsafe() function
    within file hw/display/cirrus_vga.c when handling a
    backward mode bitblt copy. A guest attacker with
    administrative privileges can exploit this to crash the
    QEMU process or potentially execute arbitrary code with
    elevated privileges. (CVE-2017-2615)

  - A flaw exists in the cirrus_bitblt_cputovideo() function
    within file hw/display/cirrus_vga.c when running in
    CIRRUS_BLTMODE_MEMSYSSRC mode due to improper memory
    region checks. A guest attacker with administrative
    privileges can exploit this to crash the QEMU process or
    potentially execute arbitrary code with elevated
    privileges. (CVE-2017-2620)");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX220771");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2017/01/24");
  script_set_attribute(attribute:"patch_publication_date",value:"2017/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/03");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:xenserver");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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

if (version == "6.0.2")
{
  fix = "XS602ECC041"; # CTX220757
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.2\.0")
{
  fix = "XS62ESP1057"; # CTX220758
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.5\.0")
{
  fix = "XS65ESP1050"; # CTX220759
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^7\.0")
{
  fix = "XS70E029"; # CTX220760
  if (fix >!< patches) vuln = TRUE;
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

if (vuln)
{
  port = 0;
  report = report_items_str(
    report_items:make_array(
      "Installed version", version,
      "Missing hotfix", fix
    ),
    ordered_fields:make_list("Installed version", "Missing hotfix")
  );
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_PATCH_INSTALLED, fix);
