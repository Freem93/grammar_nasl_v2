#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69864);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/09 15:53:04 $");

  script_cve_id(
    "CVE-2013-0711",
    "CVE-2013-0712",
    "CVE-2013-0713",
    "CVE-2013-0714",
    "CVE-2013-0715",
    "CVE-2013-0716"
  );
  script_bugtraq_id(58638, 58539, 58640, 58641, 58642, 58643);
  script_osvdb_id(91512, 91513, 91514, 91515, 91516, 91517);
  script_xref(name:"ICSA", value:"13-091-01");

  script_name(english:"VxWorks 5.5 through 6.9 Multiple Vulnerabilities");
  script_summary(english:"Checks OS fingerprint");

 script_set_attribute(attribute:"synopsis", value:
"The remote VxWorks device is potentially affected by several
vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote VxWorks device is
version 5.5 through 6.9.  It therefore is potentially affected by the
following vulnerabilities :

  - An attacker can cause SSH access to be unavailable
    until the next reboot with a specially crafted
    requests. (CVE-2013-0711 / CVE-2013-0712 /
    CVE-2013-0713)

  - An attacker can cause the server to hang and SSH access
    to be unavailable until the next reboot by sending a
    specially crafted packet for a public key
    authentication request. Arbitrary code execution is
    also a possibility. (CVE-2013-0714)

  - An attacker able to login to a CLI session can cause
    the current CLI session to crash. (CVE-2013-0715)

  - An attacker able to access the VxWorks Web Server can
    cause the server to crash using a specially crafted
    URL. (CVE-2013-0716)

Note that the Web Server and CLI vulnerabilities affect VxWorks 5.5
through 6.9 while the SSH vulnerabilities affect only versions 6.5
through 6.9.

Note that Nessus has not checked for the presence of the patch so
this finding may be a false positive.");
  script_set_attribute(attribute:"see_also", value:"http://jvn.jp/en/jp/JVN01611135/index.html");
  script_set_attribute(attribute:"see_also", value:"http://jvn.jp/en/jp/JVN20671901/index.html");
  script_set_attribute(attribute:"see_also", value:"http://jvn.jp/en/jp/JVN41022517/index.html");
  script_set_attribute(attribute:"see_also", value:"http://jvn.jp/en/jp/JVN45545972/index.html");
  script_set_attribute(attribute:"see_also", value:"http://jvn.jp/en/jp/JVN52492830/index.html");
  script_set_attribute(attribute:"see_also", value:"http://jvn.jp/en/jp/JVN65923092/index.html");
  script_set_attribute(attribute:"solution", value:"Contact the device vendor for the appropriate patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl");
  script_require_keys("Settings/ParanoidReport", "Host/OS");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

os = get_kb_item_or_exit("Host/OS");
if ("VxWorks" >!< os) audit(AUDIT_OS_NOT, "VxWorks");

match = eregmatch(pattern:"VxWorks ([0-9].+)", string:os);
if (isnull(match)) exit(1, "Failed to identify the version of VxWorks.");
version = match[1];

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version =~ "^(5\.([5-9]|[0-9][0-9]+)|6\.[0-9])($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n    Version : ' + version +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_OS_RELEASE_NOT, "VxWorks", "5.5 - 6.9", version);
