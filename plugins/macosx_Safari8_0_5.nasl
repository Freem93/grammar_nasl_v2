#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82711);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/07/03 13:25:44 $");

  script_cve_id(
    "CVE-2015-1112",
    "CVE-2015-1119",
    "CVE-2015-1120",
    "CVE-2015-1121",
    "CVE-2015-1122",
    "CVE-2015-1124",
    "CVE-2015-1126",
    "CVE-2015-1127",
    "CVE-2015-1128",
    "CVE-2015-1129"
  );
  script_bugtraq_id(
    73972,
    73973,
    73974,
    73975,
    73976,
    73977
  );
  script_osvdb_id(
    119691,
    120399,
    120400,
    120401,
    120402,
    120403,
    120404,
    120405,
    120406
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-04-08-1");

  script_name(english:"Mac OS X : Apple Safari < 6.2.5 / 7.1.5 / 8.0.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the Safari version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote Mac OS X host is
prior to 6.2.5 / 7.1.5 / 8.0.5. It is, therefore, affected by the
following vulnerabilities :

  - A flaw exists in the state management which can result
    in the user's browser history not being fully purged
    from 'history.plist'. (CVE-2015-1112)

  - Multiple memory corruption vulnerabilities exist in
    WebKit due to improperly validated user-supplied input.
    A remote attacker, using a specially crafted website,
    can exploit these issues to execute arbitrary code.
    (CVE-2015-1119, CVE-2015-1120, CVE-2015-1121,
    CVE-2015-1122, CVE-2015-1124)

  - A flaw exists in Webkit when handling credentials for
    FTP URLs. A remote attacker, using a specially crafted
    website, can cause the resources of another origin to
    be accessed. (CVE-2015-1126)

  - A flaw exists in the state management which can cause a
    user's browsing history to be indexed while in private
    mode. An attacker can use this to gain information on
    the sites that were visited. (CVE-2015-1127)

  - A flaw exists with push notification requests while in
    private browsing mode that can reveal a user's browsing
    history when responding to notifications.
    (CVE-2015-1128)

  - A flaw in client certificate matching allows a remote
    attacker, using a specially crafted website, to track a
    user's web traffic. (CVE-2015-1129)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT204658");
  # http://lists.apple.com/archives/security-announce/2015/Apr/msg00000.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?792fcba9");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Safari 6.2.5 / 7.1.5 / 8.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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

if ("10.8" >< os)
  fixed_version = "6.2.5";
else if ("10.9" >< os)
  fixed_version = "7.1.5";
else
  fixed_version = "8.0.5";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Safari", version, path);
