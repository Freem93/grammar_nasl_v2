#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95659);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/06 20:05:59 $");

  script_cve_id("CVE-2016-9637");
  script_bugtraq_id(93970);
  script_osvdb_id(148308);

  script_name(english:"Citrix XenServer QEMU ioport Array Overflow Guest-to-Host Privilege Escalation (CTX219136)");
  script_summary(english:"Checks for patches.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer running on the remote host is missing
a security hotfix. It is, therefore, affected by a privilege
escalation vulnerability in the QEMU ioport component due to an array
overflow that is triggered during the handling of addresses in ioport
read and write look-ups. A local administrative user on the guest
system can exploit this issue to gain elevated privileges on the host
system.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX219136");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/12/06");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/09");

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

if (version == "6.0.2")
{
  fix = "XS602ECC038"; # CTX219200
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.2\.")
{
  fix = "XS62ESP1053"; # CTX219201
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.5\.")
{
  fix = "XS65ESP1044"; # CTX219202
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^7\.0")
{
  fix = "XS70E022"; # CTX219203
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
