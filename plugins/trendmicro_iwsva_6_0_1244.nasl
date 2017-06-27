#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82591);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/07 13:40:41 $");

  script_cve_id("CVE-2014-8510");
  script_bugtraq_id(70964);
  script_osvdb_id(114278);

  script_name(english:"Trend Micro IWSVA < 6.0 Build 1244 Information Disclosure");
  script_summary(english:"Checks version of Trend Micro IWSVA.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Trend Micro InterScan Web
Security Virtual Appliance prior to 6.0 Build 1244. It is, therefore,
affected by an information disclosure vulnerability due to improper
validation of user-supplied configuration input when saving filters in
the AdminUI. An authenticated, remote attacker can exploit this issue
to gain access to arbitrary files which IWSVA has read access to.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-373/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Trend Micro IWSVA 6.0 Build 1244 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trendmicro:interscan_web_security_virtual_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("trendmicro_iwsva_version.nbin");
  script_require_keys("Host/TrendMicro/IWSVA/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version  = get_kb_item_or_exit("Host/TrendMicro/IWSVA/version");
build    = get_kb_item("Host/TrendMicro/IWSVA/build");

if (empty_or_null(build))
{
  if (report_paranoia > 0) build = "Unknown";
  else exit(0, "The build number of Trend Micro IWSVA could not be determined.");
}


# Version below 6.0 Build 1244 are said to be affected
fix_ver   = '6.0';
fix_build = 1244;

vuln = 0;

if (build == "Unknown")
{
  if (ver_compare(ver:version, fix:fix_ver, strict:FALSE) <= 0)
    vuln++;
}
else if (
  ver_compare(ver:version, fix:fix_ver, strict:FALSE) == -1 ||
  (ver_compare(ver:version, fix:fix_ver, strict:FALSE) == 0 &&
   build < fix_build)
  )
{
  vuln++;
}

if (vuln)
{
  port = 0;
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version + ' Build ' + build +
      '\n  Fixed version     : ' + fix_ver + ' Build ' + fix_build +
      '\n';

    security_warning(extra:report, port:port);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected.");
