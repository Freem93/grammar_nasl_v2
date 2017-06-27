#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81051);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/17 16:53:09 $");

  script_cve_id(
    "CVE-2014-3192",
    "CVE-2014-4476",
    "CVE-2014-4477",
    "CVE-2014-4479"
  );
  script_bugtraq_id(
    70273,
    72329,
    72330,
    72331
  );
  script_osvdb_id(
    112753,
    117622,
    117623,
    117624
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-01-27-3");

  script_name(english:"Mac OS X : Apple Safari < 6.2.3 / 7.1.3 / 8.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the Safari version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote Mac OS X host is
prior to 6.2.3 / 7.1.3 / 8.0.3. It is, therefore, affected by multiple
memory corruption issues in WebKit. A remote attacker, using a
specially crafted website, can exploit these to execute arbitrary
code.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/en-us/HT204243");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Safari 6.2.3 / 7.1.3 / 8.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_Safari31.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Safari/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

if (!ereg(pattern:"Mac OS X 10\.([89]|10)([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.8 / 10.9 / 10.10");

get_kb_item_or_exit("MacOSX/Safari/Installed");
path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

# Even though the fixes that the recent
# patches replace are no longer availabe,
# the older versions are checked to avoid
# FPs in the event that the initial fix
# is present
if ("10.8" >< os)
  fixed_version = "6.2.3";
else if ("10.9" >< os)
  fixed_version = "7.1.3";
else
  fixed_version = "8.0.3";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Safari", version, path);
