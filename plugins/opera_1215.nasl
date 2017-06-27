#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65927);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id("CVE-2013-3210", "CVE-2013-3211");
  script_bugtraq_id(58864, 59317);
  script_osvdb_id(91988, 91989);

  script_name(english:"Opera < 12.15 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is earlier than 12.15
and therefore is reportedly affected by the following vulnerabilities :

  - A weakness exists in the RC4 encryption protocol,
    allowing an attacker to derive the plaintext. (1046)

  - A weakness exists due to the application allowing
    cookies to be set for top-level domains, potentially
    exposing the cookie to the entire top-level domain.  A
    malicious site could redirect the user to another
    website within the same top-level domain causing it to
    reuse its cookie. (1047)

  - An unspecified, moderate severity issue exists that has an
    unspecified impact.");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/security/advisory/1046");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/security/advisory/1047");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/unified/1215/");
  script_set_attribute(attribute:"solution", value: "Upgrade to Opera 12.15 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Opera/Version");
path = get_kb_item_or_exit("SMB/Opera/Path");

version_ui = get_kb_item("SMB/Opera/Version_UI");
if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

fixed_version = "12.15.1748.0";

# Check if we need to display full version info in case of Alpha/Beta/RC
major_minor = eregmatch(string:version, pattern:"^([0-9]+\.[0-9]+)");
if (major_minor[1] == "12.15")
{
  fixed_version_report = fixed_version;
  version_report = version;
}
else fixed_version_report = "12.15";

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fixed_version_report +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Opera", version_report, path);
