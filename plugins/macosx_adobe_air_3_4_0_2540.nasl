#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(61625);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id(
    "CVE-2012-4163",
    "CVE-2012-4164",
    "CVE-2012-4165",
    "CVE-2012-4167",
    "CVE-2012-4168",
    "CVE-2012-4171"
  );
  script_bugtraq_id(55365, 56189, 56191, 56192, 56196, 56197, 56199);
  script_osvdb_id(84789, 84790, 84791, 84792, 84793, 84794, 85260);

  script_name(english:"Adobe AIR for Mac 3.x <= 3.3.0.3670 Multiple Vulnerabilities (APSB12-19)");
  script_summary(english:"Checks version gathered by local check");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host contains a version of Adobe AIR that is
affected by multiple security vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the instance of Adobe AIR on the remote
Mac OS X host is 3.3.0.3670 or earlier and is, therefore, reportedly
affected by multiple vulnerabilities :

  - Multiple memory corruption vulnerabilities could lead to
    code execution. (CVE-2012-4163, CVE-2012-4164,
    CVE-2012-4165)

  - An integer overflow vulnerability exists which could
    lead to code execution. (CVE-2012-4167)

  - A cross-domain information leak vulnerability exists.
    (CVE-2012-4168)

  - A crash can be caused by a logic error involving
    multiple dialogs in Firefox. (CVE-2012-4171)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-19.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe AIR 3.4 (3.4.0.2540) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/22");


  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_adobe_air_installed.nasl");
  script_require_keys("MacOSX/Adobe_AIR/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


kb_base = "MacOSX/Adobe_AIR";
version = get_kb_item_or_exit(kb_base+"/Version");
path = get_kb_item_or_exit(kb_base+"/Path");

# nb: we're checking for versions less than *or equal to* the cutoff!
cutoff_version = '3.3.0.3670';
fixed_version_for_report = '3.4.0.2540';

if (version =~ '^3\\.' && ver_compare(ver:version, fix:cutoff_version, strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : '+fixed_version_for_report+'\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Adobe AIR", version, path);
