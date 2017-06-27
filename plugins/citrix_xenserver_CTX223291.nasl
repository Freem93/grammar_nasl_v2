#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100104);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/11 15:29:11 $");

  script_osvdb_id(156796, 156797, 156798);
  script_xref(name:"IAVA", value:"2017-A-0135");

  script_name(english:"Citrix XenServer Multiple Vulnerabilities (CTX223291)");
  script_summary(english:"Checks for patches.");

  script_set_attribute(attribute:"synopsis", value:
"A server virtualization platform installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer running on the remote host is missing
a security hotfix. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists that is triggered when
    handling grant transfers. An attacker in a guest virtual
    machine can exploit this to gain elevated privileges on
    the host. (VulnDB 156796)

  - A memory corruption issue exists due to improper
    validation of user-supplied input when handling failsafe
    callbacks. An attacker in a guest virtual machine can
    exploit this to corrupt memory, resulting in a denial of
    service condition or the execution of arbitrary code on
    the host. (VulnDB 156797)

  - An unspecified flaw exists when handling
    use-after-mode-change pagetables. An attacker in a guest
    virtual machine can exploit this to gain elevated
    privileges on the host. (VulnDB 156798)");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX223291");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date",value:"2017/05/02");
  script_set_attribute(attribute:"patch_publication_date",value:"2017/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:xenserver");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  fix = "XS602ECC044"; # CTX223286
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.2\.0")
{
  fix = "XS62ESP1060"; # CTX223287
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.5($|[^0-9])")
{
  fix = "XS65ESP1054"; # CTX223288
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^7\.0($|[^0-9])")
{
  fix = "XS70E034"; # CTX223289
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^7\.1($|[^0-9])")
{
  fix = "XS71E007"; # CTX223290
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
