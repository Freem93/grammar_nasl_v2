# @DEPRECATED@
#
# This script has been deprecated as only the SDK itself is affected.
#
# Disabled on 2014/07/10.
#

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76414);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/07/28 20:23:55 $");

  script_cve_id("CVE-2014-0537", "CVE-2014-0539", "CVE-2014-4671");
  script_bugtraq_id(68454, 68455, 68457);
  script_osvdb_id(108799, 108800, 108828);

  script_name(english:"Adobe AIR for Mac <= 14.0.0.110 Multiple Vulnerabilities (APSB14-17)");
  script_summary(english:"Checks the version gathered by local check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a version of Adobe AIR that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the instance of Adobe AIR on the remote Mac
OS X host is equal or prior to 14.0.0.110. It is, therefore, affected
by the following vulnerabilities :

  - A CSRF bypassing Same Origin Policy vulnerability
    exists that could leak potentially sensitive data.
    (CVE-2014-4671)

  - Multiple unspecified errors exist that could allow
    unspecified security bypass attacks. (CVE-2014-0537,
    CVE-2014-0539)");
  script_set_attribute(attribute:"see_also", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-17.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe AIR 14.0.0.137 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_adobe_air_installed.nasl");
  script_require_keys("MacOSX/Adobe_AIR/Version");

  exit(0);
}

# Deprecated.
exit(0, "The patch in APSB14-17 is for Adobe AIR SDK and Compiler.");


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "MacOSX/Adobe_AIR";
version = get_kb_item_or_exit(kb_base+"/Version");
path = get_kb_item_or_exit(kb_base+"/Path");

# nb: we're checking for versions less than *or equal to* the cutoff!
cutoff_version = '14.0.0.110';
fixed_version_for_report = '14.0.0.137';

if (ver_compare(ver:version, fix:cutoff_version, strict:FALSE) <= 0)
{
  set_kb_item(name:'www/0/XSRF', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version_for_report +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Adobe AIR", version, path);
