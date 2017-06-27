#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77174);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/20 14:12:04 $");

  script_cve_id(
    "CVE-2014-0538",
    "CVE-2014-0540",
    "CVE-2014-0541",
    "CVE-2014-0542",
    "CVE-2014-0543",
    "CVE-2014-0544",
    "CVE-2014-0545",
    "CVE-2014-5333"
  );
  script_bugtraq_id(
    69190,
    69191,
    69192,
    69194,
    69195,
    69196,
    69197,
    69320
  );

  script_name(english:"Flash Player for Mac <= 14.0.0.145 Multiple Vulnerabilities (APSB14-18)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a browser plugin that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the instance of Flash Player installed on
the remote Mac OS X host is equal or prior to 14.0.0.145. It is,
therefore, affected by the following vulnerabilities :

  - A use-after-free error exists that allows code
    execution. (CVE-2014-0538)

  - An unspecified security bypass error exists.
    (CVE-2014-0541)

  - Multiple errors exist related to memory leaks that can
    be used to bypass memory address randomization.
    (CVE-2014-0540, CVE-2014-0542, CVE-2014-0543,
    CVE-2014-0544, CVE-2014-0545)");
  script_set_attribute(attribute:"see_also", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-18.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 14.0.0.176 or later.

Alternatively, Adobe has made version 13.0.0.241 available for those
installations that cannot be upgraded to 14.x.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_flash_player_installed.nasl");
  script_require_keys("MacOSX/Flash_Player/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("MacOSX/Flash_Player/Version");
path = get_kb_item_or_exit("MacOSX/Flash_Player/Path");

if (ver_compare(ver:version, fix:"14.0.0.0", strict:FALSE) >= 0)
{
  cutoff_version = "14.0.0.145";
  fix = "14.0.0.176";
}
else
{
  cutoff_version = "13.0.0.231";
  fix = "13.0.0.241";
}

# nb: we're checking for versions less than *or equal to* the cutoff!
if (ver_compare(ver:version, fix:cutoff_version, strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Flash Player for Mac", version, path);
