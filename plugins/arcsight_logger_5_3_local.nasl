#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69444);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/09/20 04:38:52 $");

  script_cve_id(
    "CVE-2012-2960",
    "CVE-2012-3286",
    "CVE-2012-5198",
    "CVE-2012-5199"
  );
  script_bugtraq_id(54824, 57975, 57976, 57978);
  script_osvdb_id(84588, 90284, 90285, 90286);
  script_xref(name:"CERT", value:"829260");
  script_xref(name:"CERT", value:"960468");
  script_xref(name:"CERT", value:"988100");

  script_name(english:"HP ArcSight Logger < 5.3 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks ArcSight Logger version number");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A log collection and management system on the remote host has 
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the version of HP
ArcSight Logger installed on the remote host is affected by the
following vulnerabilities :

  - An error exists related to handling host file imports
    that could allow cross-site scripting attacks.
    (CVE-2012-2960)

  - An unspecified error exists that could allow a remote
    attacker to inject commands. (CVE-2012-3286)

  - An unspecified error exists that could allow
    unspecified information disclosure. (CVE-2012-5198)

  - An unspecified error exists that could allow a local
    attacker to inject commands. (CVE-2012-5199)"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03606700
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1858a65c");
  script_set_attribute(attribute:"solution", value:"Upgrade to ArcSight Logger 5.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:arcsight_logger");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("arcsight_logger_installed_linux.nasl");
  script_require_keys("hp/arcsight_logger/ver");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_internals.inc");

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

port = 0;
ver = get_kb_item_or_exit("hp/arcsight_logger/ver");
path = get_kb_item_or_exit("hp/arcsight_logger/path");

if (ver == 'unknown')
  exit(1, "The version of ArcSight Logger at "+path+" is unknown.");

display_ver = get_kb_item("hp/arcsight_logger/display_ver");

if (isnull(display_ver))
  display_ver = ver;

fix = '5.3';
display_fix = '5.3 (5.3)';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'ArcSight Logger', display_ver);

if (report_verbosity > 0)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);

  # if the version is in the KB the path should be there as well,
  # but this code will be defensive anyway
  if (isnull(path))
    path = 'n/a';

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + display_ver +
    '\n  Fixed version     : ' + display_fix + '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
