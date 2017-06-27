#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93608);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/02/06 20:05:59 $");

  script_cve_id(
    "CVE-2016-7092",
    "CVE-2016-7093",
    "CVE-2016-7094",
    "CVE-2016-7154"
  );
  script_bugtraq_id(
    92862,
    92863,
    92864,
    92865
  );
  script_osvdb_id(
    143907,
    143908,
    143909,
    143916
  );

  script_name(english:"Citrix XenServer Multiple Vulnerabilities (CTX216071)");
  script_summary(english:"Checks for patches.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer running on the remote host is missing
a security hotfix. It is, therefore, affected by multiple
vulnerabilities :

  - A flaw exists due to improper handling of pagetable
    walks that contain recursive L3 pagetable entries. An
    attacker on the guest can exploit this to gain elevated
    privileges. (CVE-2016-7092)

  - A flaw exists due to improper handling of instruction
    pointer truncation when emulating HVM instructions. An
    attacker on the guest can exploit this to gain elevated
    privileges. (CVE-2016-7093)

  - An overflow condition exists in the x86 HVM guests due
    to improper handling of writing to pagetables,
    specifically when the guest is running shadow paging
    using a subset of the x86 emulator. An attacker on the
    guest can exploit this to cause a denial of service
    condition on the host. (CVE-2016-7094)

  - A use-after-free error exists when calling the
    EVTCHNOP_init_control operation with a bad guest frame
    number. An attacker on the guest can exploit this, by
    freeing a control structure without also clearing the
    corresponding pointer, to crash the host or potentially
    gain elevated privileges. (CVE-2016-7154)");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX216071");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/09/08");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/20");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:xenserver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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

if (version == "6.0.0")
{
  fix = "XS60E063";
  if (fix >!< patches) vuln = TRUE;
}
else if (version == "6.0.2")
{
  fix = "XS602E057 or XS602ECC034";
  if (("XS602E057" >!< patches) && ("XS602ECC034" >!< patches)) vuln = TRUE;
}
else if (version =~ "^6\.1\.")
{
  fix = "XS61E073";
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.2\.")
{
  fix = "XS62ESP1048";
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.5\.")
{
  fix = "XS65ESP1038";
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^7\.0")
{
  fix = "XS70E012";
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
