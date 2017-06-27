#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72174);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id("CVE-2014-0494");
  script_bugtraq_id(65091);
  script_osvdb_id(102364);

  script_name(english:"Adobe Digital Editions 2.0.1 Memory Corruption (Mac OS X)");
  script_summary(english:"Checks version of Adobe Digital Editions on Mac OS X");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of Adobe Digital Editions on the remote Mac OS X host
is affected by a memory corruption vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Adobe Digital Editions installed on the remote
Mac OS X host is 2.0.1. It is, therefore, affected by an unspecified
memory corruption vulnerability that could allow denial of service
attacks and possibly arbitrary code execution."
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Digital Editions 3.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  #http://helpx.adobe.com/security/products/Digital-Editions/apsb14-03.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?abe555c7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:digital_editions");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_adobe_digital_editions_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Adobe Digital Editions/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

version = get_kb_item_or_exit("MacOSX/Adobe Digital Editions/Version");
ver_ui  = get_kb_item("MacOSX/Adobe Digital Editions/Version_UI");

fixed_version = "3.0 (3.0.86137)";

# Affected :
# 2.0.1
if (version =~ "^2\.0\.1($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    if (ver_ui)
      report =
        '\n  Installed version : ' + version + ' ('+ver_ui+')' +
        '\n  Fixed version     : ' + fixed_version + '\n';
    else
      report =
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Adobe Digital Editions", version);
