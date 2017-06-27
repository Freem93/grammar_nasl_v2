#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68857);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/21 20:34:20 $");

  script_name(english:"Oracle Linux Update Release");
  script_summary(english:"Check for Oracle Linux release");

  script_set_attribute(attribute:"synopsis", value:"The remote Oracle Linux operating system is out-of-date.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a release of Oracle Linux that is not at
the latest update release (or minor release). Since updating Oracle
Linux to the latest update release provides a host with the most
recent updates, this means that it has not been updated recently and
is likely to be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://blogs.oracle.com/OTNGarage/entry/how_the_oracle_linux_update");
  script_set_attribute(attribute:"solution", value:"Apply the latest update release.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");


lastupdate[4] = 9;
lastupdate[5] = 11;
lastupdate[6] = 6;
lastupdate[7] = 0;

rel = get_kb_item("Host/RedHat/release");
if (!rel)
{
  rpm_list = get_kb_item("Host/RedHat/rpm-list");
  if (rpm_list) audit(AUDIT_PACKAGE_LIST_MISSING);

  lines = egrep(string:rpm_list, pattern: "^oraclelinux-release-[0-9]");
  if (!lines) exit(1, "oraclelinux-release was not found in the list of installed RPMs.");
  match = eregmatch(string:lines, pattern: "oraclelinux-release-([0-9]+)Server-([0-9]+)");
  if (isnull(match)) match = eregmatch(string:lines, pattern: "oraclelinux-release-([0-9]+)-([0-9]+)");
  if (isnull(match)) exit(1, "Could not parse Oracle Linux release version from "+lines+".");
  rel = match[1] + "." + match[2];
}

match = eregmatch(string:rel, pattern:"release ([0-9]+)\.([0-9]+)");
if (isnull(match)) exit(1, "Could not parse the Oracle Linux release string ("+rel+").");
major = int(match[1]);
minor = int(match[2]);

if (isnull(lastupdate[major])) exit(1, "Unknown update release ("+minor+") for Oracle Linux "+major+".");

if (minor < lastupdate[major])
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + major + '.' + minor +
      '\n  Latest version    : ' + major + '.' + lastupdate[major];
    security_hole(port:0, extra:report);
  }
  else security_hole(0);

  exit(0);
}
else exit(0, "The host is running Oracle Linux "+major+"."+minor+", which is the latest update release for Oracle Linux "+major+".x.");
