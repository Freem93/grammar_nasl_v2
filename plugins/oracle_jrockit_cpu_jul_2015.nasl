#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84808);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/07 18:00:12 $");

  script_cve_id(
    "CVE-2015-2601",
    "CVE-2015-2625",
    "CVE-2015-2808",
    "CVE-2015-4000",
    "CVE-2015-4748",
    "CVE-2015-4749"
  );
  script_bugtraq_id(
    73684,
    74733,
    75854,
    75867,
    75890,
    75895
  );
  script_osvdb_id(
    124629,
    124639,
    117855,
    122331,
    124625,
    124636
  );

  script_name(english:"Oracle JRockit R28 < R28.3.7 Multiple Vulnerabilities (July 2015 CPU) (Bar Mitzvah) (Logjam)");
  script_summary(english:"Checks the version of jvm.dll.");

  script_set_attribute(attribute:"synopsis", value:
"A programming platform installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle JRockit installed on the remote Windows host is
R28 prior to R28.3.7. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists in the JCE component that
    allows a remote attacker to gain access to sensitive
    information. (CVE-2015-2601)

  - An unspecified flaw exists in the JSSE component when
    handling the SSL/TLS protocol. A remote attacker can
    exploit this to gain access to sensitive information.
    (CVE-2015-2625)

  - A security feature bypass vulnerability exists, known as
    Bar Mitzvah, due to improper combination of state data
    with key data by the RC4 cipher algorithm during the
    initialization phase. A man-in-the-middle attacker can
    exploit this, via a brute-force attack using LSB values,
    to decrypt the traffic. (CVE-2015-2808)

  - A man-in-the-middle vulnerability, known as Logjam,
    exists due to a flaw in the SSL/TLS protocol. A remote
    attacker can exploit this flaw to downgrade connections
    using ephemeral Diffie-Hellman key exchange to 512-bit
    export-grade cryptography. (CVE-2015-4000)

  - An unspecified flaw exists in the Security component
    when handling the Online Certificate Status Protocol
    (OCSP). A remote attacker can exploit this to execute
    arbitrary code. (CVE-2015-4748)

  - An unspecified flaw exists in the JNDI component that
    allows a remote attacker to cause a denial of service.
    (CVE-2015-4749)");
  # http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d18c2a85");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JRockit version R28.3.7 or later as referenced in
the July 2015 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jrockit");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_jrockit_installed.nasl");
  script_require_keys("installed_sw/Oracle JRockit");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app     = "Oracle JRockit";
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
ver     = install['version'];
type    = install['type'];
path    = install['path'];

if (ver =~ "^28(\.3)?$") audit(AUDIT_VER_NOT_GRANULAR, app, ver);
if (ver !~ "^28\.3($|[^0-9])") audit(AUDIT_NOT_INST, app + " 28.3.x");

# Affected :
# 28.3.6.x
if (ver =~ "^28\.3\.6($|[^0-9])")
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    # The DLL we're looking at is a level deeper in the JDK, since it
    # keeps a subset of the JRE in a subdirectory.
    if (type == "JDK")  path += "\jre";
    path += "\bin\jrockit\jvm.dll";

    report =
      '\n  Type              : ' + type +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver  +
      '\n  Fixed version     : 28.3.7'  +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);
