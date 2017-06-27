#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(97998);
  script_version ("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/11 18:57:10 $");

  script_cve_id("CVE-2017-5689");
  script_bugtraq_id(98269);
  script_osvdb_id(156732);
  script_xref(name:"CERT", value:"491375");
  script_xref(name:"IAVA", value:"2017-A-0131");

  script_name(english:"Intel Management Engine Insecure Read / Write Operations RCE (INTEL-SA-00075) (remote check)");
  script_summary(english:"Checks the version of Intel manageability firmware via server header.");

  script_set_attribute(attribute:"synopsis", value:
"The management engine on the remote host is affected by a remote code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Intel Management Engine on the remote host has Active Management
Technology (AMT) enabled, and according to its self-reported version
in the banner, it is running Intel manageability firmware version 6.x
prior to 6.2.61.3535, 7.x prior to 7.1.91.3272, 8.x prior to
8.1.71.3608, 9.0.x or 9.1.x prior to 9.1.41.3024, 9.5.x prior to
9.5.61.3012, 10.0.x prior to 10.0.55.3000, 11.0.18.x prior to
11.0.18.3003, 11.0.22.x prior to 11.0.22.3001, 11.0.x prior to
11.0.25.3001, 11.6.12.x prior to 11.6.12.3202, or else 11.5.x or
11.6.x prior to 11.6.27.3264. It is, therefore, affected by a remote
code execution vulnerability due to insecure read and write
operations. An unauthenticated, remote attacker can exploit this to
execute arbitrary code.

Note that the vulnerability is only exploitable remotely if either
Active Management Technology (AMT), Intel Standard Manageability
(ISM), or Small Business Technology (SBT) is enabled. However, a local
attacker can still exploit the vulnerability even if these components
are disabled by simply re-enabling the components.");
  # https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00075&languageid=en-fr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e6ca5f4");
  script_set_attribute(attribute:"see_also", value:"https://downloadcenter.intel.com/download/26754");
  script_set_attribute(attribute:"see_also", value:"https://mjg59.dreamwidth.org/48429.html");
  script_set_attribute(attribute:"see_also", value:"https://www.embedi.com/news/mythbusters-cve-2017-5689");
  script_set_attribute(attribute:"solution", value:
"Contact your system OEM for updated firmware per the vendor advisory.

Alternatively, apply these mitigations per the INTEL-SA-00075
mitigation guide :

  - Unprovision Intel manageability SKU clients.
  - Disable or remove the Local Manageability Service (LMS).
  - Configure local manageability configuration restrictions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:intel:active_management_technology");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 16992, 16993, 16994, 16995, 623, 664);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

port = get_http_port(default:16992);

service = "Intel Active Management Technology";
banner = get_http_banner(port:port);

if (banner !~ "Server: (AMT|Intel\(R\) (Active Management Technology|Standard Manageability))")
  audit(AUDIT_NOT_LISTEN, service, port);
else banner = strstr(banner, "Server:"); # slice banner

# check for just AMT, which does not have any version info
if (banner =~ "^Server: AMT$") audit(AUDIT_UNKNOWN_WEB_SERVER_VER, service, port);

# otherwise get Intel Manageability firmware version
pat = "^Server: Intel\(R\) (?:Active Management Technology|Standard Manageability) ([0-9.]+)";
version = pregmatch(string:banner, pattern:pat);
if (isnull(version)) audit(AUDIT_NOT_LISTEN, service, port);
else version = version[1];

if (version =~ "^6\.[012]\.")
{
  fix = "6.2.61";
  fix_disp = "6.2.61.3535";
}
else if (version =~ "^7\.[01]\.")
{
  fix = "7.1.91";
  fix_disp = "7.1.91.3272";
}
else if (version =~ "^8\.[01]\.")
{
  fix = "8.1.71";
  fix_disp = "8.1.71.3608";
}
else if (version =~ "^9\.[01]\.")
{
  fix = "9.1.41";
  fix_disp = "9.1.41.3024";
}
else if (version =~ "^9\.5\.")
{
  fix = "9.5.61";
  fix_disp = "9.5.61.3012";
}
else if (version =~ "^10\.0\.")
{
  fix = "10.0.55";
  fix_disp = "10.0.55.3000";
}
else if (version =~ "^11\.0\.18($|[^0-9])")
{
  fix = "11.0.18";
  fix_disp = "11.0.18.3003";
}
else if (version =~ "^11\.0\.22($|[^0-9])")
{
  fix = "11.0.22";
  fix_disp = "11.0.22.3001";
}
else if (version =~ "^11\.0\.")
{
  fix = "11.0.25";
  fix_disp = "11.0.25.3001";
}
else if (version =~ "^11\.6\.12($|[^0-9])")
{
  fix = "11.6.12";
  fix_disp = "11.6.12.3202";
}
else if (version =~ "^11\.[56]\.")
{
  fix = "11.6.27";
  fix_disp = "11.6.27.3264";
}
else
  audit(AUDIT_LISTEN_NOT_VULN, service, port, version);

# the one case we can't be sure it's vuln/patched
if (ver_compare(ver:version, fix:fix, strict:FALSE) == 0)
  audit(AUDIT_VER_NOT_GRANULAR, service, port, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  order = make_list('Intel Manageability Firmware', 'Fixed Firmware');
  report = make_array(
    order[0], version,
    order[1], fix_disp
  );

  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, service, port, version);
