#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99377);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/12 17:36:03 $");

  script_cve_id(
    "CVE-2016-10013",
    "CVE-2017-7228"
  );
  script_bugtraq_id(
    94963,
    97375
  );
  script_osvdb_id(
    149021,
    152191,
    154912
  );

  script_name(english:"Citrix XenServer multiple vulnerabilities (CTX222565)");
  script_summary(english:"Checks for patches.");

  script_set_attribute(attribute:"synopsis", value:
"A server virtualization platform installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer installed on the remote host is
missing a security hotfix. It is, therefore, affected by multiple
vulnerabilities :

  - A flaw exists when invoking the instruction emulator
    that is triggered during the handling of SYSCALL by
    single-stepping applications. A local attacker can
    exploit this to execute code with elevated privileges
    on the guest. (CVE-2016-10013)

  - An out-of-array memory access error exists in the
    memory_exchange() function within file common/memory.c
    due to improper checking of XENMEM_exchange input. An
    attacker on a 64-bit PV guest VM who has administrative
    privileges can exploit this issue to access arbitrary
    system memory locations, which can then be potentially
    used for further compromising the host. (CVE-2017-7228)

  - A memory leak issue exits due to improper cleanup being
    performed during guest destruction. An attacker on the
    guest can exploit this, by repeatedly rebooting, to
    exhaust memory on the host system, resulting in a denial
    of service condition. (VulnDB 152191)");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX222565");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/12/19");
  script_set_attribute(attribute:"patch_publication_date",value:"2017/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:xenserver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("citrix_xenserver_version.nbin");
  script_require_keys("Host/XenServer/version", "Host/local_checks_enabled", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = "Citrix XenServer";
version = get_kb_item_or_exit("Host/XenServer/version");
get_kb_item_or_exit("Host/local_checks_enabled");
patches = get_kb_item("Host/XenServer/patches");
vuln = FALSE;
fix = '';

if (version == "6.0.2")
{
  fix = "XS602ECC043"; # CTX222420
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.2\.0")
{
  fix = "XS62ESP1059"; # CTX222421
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.5")
{
  fix = "XS65ESP1053"; # CTX222422
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^7\.0($|[^0-9])")
{
  fix = "XS70E032"; # CTX222423
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^7\.1($|[^0-9])")
{
  fix = "XS71E006"; # CTX222424
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
