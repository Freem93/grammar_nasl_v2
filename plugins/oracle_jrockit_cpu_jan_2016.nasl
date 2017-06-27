#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88041);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 18:52:13 $");

  script_cve_id(
    "CVE-2015-7575",
    "CVE-2016-0483",
    "CVE-2016-0475",
    "CVE-2016-0466"
  );
  script_bugtraq_id(79684);
  script_osvdb_id(
    132305,
    133157,
    133158,
    133160
  );

  script_name(english:"Oracle JRockit R28 < R28.3.9 Multiple Vulnerabilities (January 2016 CPU) (SLOTH)");
  script_summary(english:"Checks the version of jvm.dll.");

  script_set_attribute(attribute:"synopsis", value:
"A programming platform installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle JRockit installed on the remote Windows host is
R28 prior to R28.3.9. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists in the Security subcomponent
    due to a failure to reject MD5 signatures in the server
    signature within the TLS 1.2 ServerKeyExchange messages.
    A man-in-the-middle attacker, by triggering collisions,
    can exploit this issue to spoof servers. (CVE-2015-7575)

  - A memory corruption issue exists in the AWT subcomponent
    when decoding JPEG files. A remote attacker can exploit
    this to execute arbitrary code. (CVE-2016-0483)

  - A collision-based forgery vulnerability, known as SLOTH
    (Security Losses from Obsolete and Truncated Transcript
    Hashes), exists in the TLS protocol due to accepting
    RSA-MD5 signatures in the server signature within the
    TLS 1.2 ServerKeyExchange messages during a TLS
    handshake. A man-in-the-middle attacker can exploit
    this, via a transcript collision attack, to impersonate
    a TLS server. (CVE-2015-7575) (CVE-2016-0475)

  - A denial of service vulnerability exists in the JAXP
    subcomponent during the handling of expanded general
    entities. A remote attacker can exploit this to bypass
    the 'totalEntitySizeLimit' restrictions and exhaust
    available memory. (CVE-2016-0466)");
  # http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da1a16c5");
  script_set_attribute(attribute:"see_also", value:"http://www.mitls.org/pages/attacks/SLOTH");
  script_set_attribute(attribute:"see_also", value:"http://www.mitls.org/downloads/transcript-collisions.pdf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JRockit version R28.3.9 or later as referenced in
the January 2016 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jrockit");

  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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
# 28.3.8.x
if (ver =~ "^28\.3\.8($|[^0-9])")
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
      '\n  Fixed version     : 28.3.9'  +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);
