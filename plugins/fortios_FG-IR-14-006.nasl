#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77988);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/23 20:09:18 $");

  script_cve_id("CVE-2014-2216", "CVE-2014-0351");
  script_bugtraq_id(69338, 69754);
  script_osvdb_id(110264, 111310);
  script_xref(name:"CERT", value:"730964");

  script_name(english:"Fortinet FortiOS < 4.3.16 / 5.x < 5.0.8 Multiple Vulnerabilities (FG-IR-14-006)");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running FortiOS prior to 4.3.16 or 5.x prior to
5.0.8. It is, therefore, affected by the following vulnerabilities :

  - A flaw exists within the FortiManager service when
    handling incoming requests. Using a specially crafted
    request, a remote attacker can exploit this to cause a
    denial of service or possibly execute arbitrary code.
    (CVE-2014-2216)

  - A flaw exists within the FortiManager communications
    protocol that allows a man-in-the-middle attacker,
    using an anonymous cipher suite, to acquire sensitive
    information or otherwise impact host communications.
    (CVE-2014-0351)");
  script_set_attribute(attribute:"see_also", value:"http://www.fortiguard.com/advisory/FG-IR-14-006");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS 4.3.16 / 5.0.8 / 5.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version", "Host/Fortigate/build", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "FortiOS";

model = get_kb_item_or_exit("Host/Fortigate/model");

# Make sure device is FortiGate or FortiWiFi.
if (!preg(string:model, pattern:"forti(gate|wifi)", icase:TRUE)) audit(AUDIT_HOST_NOT, "a FortiGate or FortiWiFi");

version = get_kb_item_or_exit("Host/Fortigate/version");
build = get_kb_item_or_exit("Host/Fortigate/build");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Versions < 4.3.16 /  5.x < 5.0.8 is affected.
if (version =~ "^[0-4]\.")
{
  fix = "4.3.16";
  fix_build = 686;
}
else if (version =~ "^5\.0\.")
{
  fix = "5.0.8";
  fix_build = 291;
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

# If build number is available, this is the safest comparison.
# Otherwise compare version numbers.
vuln = FALSE;
if (build !~ "Unknown")
{
  if (int(build) < fix_build) vuln = TRUE;
}
else if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1) vuln = TRUE;

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(extra:report, port:0);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
