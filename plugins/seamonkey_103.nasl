#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22097);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/05/13 15:33:29 $");

  script_cve_id("CVE-2006-3113", "CVE-2006-3677", "CVE-2006-3801", "CVE-2006-3802",
                "CVE-2006-3803", "CVE-2006-3804", "CVE-2006-3805", "CVE-2006-3806",
                "CVE-2006-3807", "CVE-2006-3808", "CVE-2006-3809", "CVE-2006-3810",
                "CVE-2006-3811", "CVE-2006-3812");
  script_bugtraq_id(19181, 19192, 19197);
  script_osvdb_id(
    27558,
    27559,
    27560,
    27561,
    27562,
    27563,
    27564,
    27565,
    27566,
    27567,
    27568,
    27569,
    27570,
    27571,
    27572,
    27573,
    27574,
    27575,
    27576,
    27577,
    94469,
    94470,
    94471,
    94472,
    94473,
    94474,
    94475
  );
  script_xref(name:"CERT", value:"655892");

  script_name(english:"SeaMonkey < 1.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is prone to multiple flaws.");
  script_set_attribute(attribute:"description", value:
"The installed version of SeaMonkey contains various security issues,
some of which could lead to execution of arbitrary code on the affected
host subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-44.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-45.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-46.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-47.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-48.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-49.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-50.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-51.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-52.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-53.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-54.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-55.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2006/mfsa2006-56.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to SeaMonkey 1.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Suite/Firefox Navigator Object Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");


  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/SeaMonkey/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "SeaMonkey");

mozilla_check_version(installs:installs, product:'seamonkey', fix:'1.0.3', severity:SECURITY_HOLE);
